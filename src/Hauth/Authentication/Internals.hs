module Hauth.Authentication.Internals
(
  buildAuthenticatorPair
, AuthenticationGuard
, Authenticator
) where

import           Control.Monad
import           Control.Monad.IO.Class
import qualified Data.Aeson                        as A
import qualified Data.ByteString.Lazy              as BS
import           Data.Maybe
import qualified Data.Text                         as T
import           Data.Time.Clock
import           Data.UUID                         (UUID)
import qualified Data.UUID                         as U hiding (UUID)
import           Data.UUID.V4
import           Hauth.Authentication
import           Hauth.Authentication.CookieHelper
import           Jose.Jwe
import           Jose.Jwk
import           Jose.Jwt
import           Network.HTTP.Types.Header
import           Network.HTTP.Types.Status
import           Network.Wai
import           Web.Cookie
import           Web.Scotty
import           Web.Scotty.Cookie

newtype EncryptionKey = EK Jwk
newtype AppClaims = AC Payload

type AuthenticationGuard = ActionM UUID
type Authenticator       = UUID -> ActionM ()

type AuthenticationResult = (AuthenticationGuard, Authenticator)

buildAuthenticatorPair :: AuthenticationConfig -> IO AuthenticationResult
buildAuthenticatorPair c = do
  k <- getAESKey (encryptionConfig c)
  return (authenticationGuard c k, authenticator c k)

authenticator :: AuthenticationConfig -> EncryptionKey -> Authenticator
authenticator c k uuid =
  liftIO (encryptJwt ec k claims) >>= handleEncryptionResult cc
  where ec     = encryptionConfig c
        cc     = cookieConfig c
        claims = mkClaims (applicationName c) (U.toText uuid)

authenticationGuard :: AuthenticationConfig -> EncryptionKey -> ActionM UUID
authenticationGuard c k =
  maybe denyAccess authenticate =<< getJwtFromRequest cconfig <$> request
  where cconfig          = cookieConfig c
        authenticate jwt = liftIO (decryptJwt k jwt) >>= handleDecryptionResult c

denyAccess :: ActionM a
denyAccess = status status403 >> finish

handleEncryptionResult :: CookieConfig -> Either JwtError Jwt -> ActionM ()
handleEncryptionResult c (Left err)  = logJwtError err >> status status403
handleEncryptionResult c (Right jwt) = do
  t <- liftIO getCurrentTime
  setCookie $ mkCookie c t jwt

handleDecryptionResult :: AuthenticationConfig -> Either JwtError JwtContent -> ActionM UUID
handleDecryptionResult c (Left err) = logJwtError err >> denyAccess
handleDecryptionResult c (Right j)  = handleClaims j
  where handleClaims (Jwe (_, bs)) = maybe denyAccess return $ uuidFromClaims bs
        handleClaims _             = unexpectedJwtFormat
        uuidFromClaims bs = do
          claims <- A.decode $ BS.fromStrict bs
          valid  <- validateClaims claims
          if valid then extractUUID claims else Nothing
        validateClaims = fmap (== applicationName c) . jwtIss
        extractUUID    = join . fmap U.fromText . jwtSub

unexpectedJwtFormat :: ActionM a
unexpectedJwtFormat = liftIO (print "Unexpected JWT Format") >> denyAccess

logJwtError :: JwtError -> ActionM ()
logJwtError = liftIO . Prelude.putStrLn . mappend "JwtError: " . show

-- Using our encryption config, build our encryption key for the app
getAESKey :: EncryptionConfig -> IO EncryptionKey
getAESKey c = EK <$>
  generateSymmetricKey keyLength (KeyId keyID) Enc Nothing
  where keyLength = keyLen c
        keyID     = keyId c

-- Using our built encryption key, the encryption config, and claims,
-- encodes claims in an encrypted JWT.
encryptJwt :: EncryptionConfig -> EncryptionKey -> AppClaims -> IO (Either JwtError Jwt)
encryptJwt c (EK aesKey) (AC cs) = jwkEncode alg enc aesKey cs
  where alg = algorithm c
        enc = encryption c

-- Using our built encryption key, decrypt the JWT from the cookie.
decryptJwt :: EncryptionKey -> Jwt -> IO (Either JwtError JwtContent)
decryptJwt (EK aesKey) (Jwt bs) = jwkDecode aesKey bs

-- Get the JWT for the app out of the cookie request headers.
getJwtFromRequest :: CookieConfig -> Request -> Maybe Jwt
getJwtFromRequest c = join                .
                      fmap (fmap Jwt    .
                            lookup name .
                            parseCookies) .
                      lookup hCookie      .
                      requestHeaders
  where name = cookieName c

mkCookie :: CookieConfig -> UTCTime -> Jwt -> SetCookie
mkCookie c t (Jwt j) = def {
    setCookieName     = cookieName c
  , setCookieValue    = j
  , setCookieHttpOnly = True
  , setCookiePath     = Just $ cookiePath c
  , setCookieExpires  = Just $ secondsFromConfig `addUTCTime` t
  }
  where secondsFromConfig = secondsForExpiration $ cookieExpiration c

mkClaims :: T.Text -> T.Text -> AppClaims
mkClaims iss sub = AC . Claims . BS.toStrict $ A.encode JwtClaims {
    jwtIss = Just iss
  , jwtSub = Just sub
  , jwtAud = Nothing
  , jwtExp = Nothing
  , jwtNbf = Nothing
  , jwtIat = Nothing
  , jwtJti = Nothing
  }
