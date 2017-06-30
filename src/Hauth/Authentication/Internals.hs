{-# LANGUAGE OverloadedStrings #-}

module Hauth.Authentication.Internals
(
  buildAuthenticatorPair
, AuthenticationGuard
, Authenticator
) where

import           Control.Applicative
import           Control.Monad
import           Control.Monad.IO.Class
import qualified Data.Aeson                        as A
import qualified Data.ByteString                   as B
import qualified Data.ByteString.Lazy              as BS
import           Data.Maybe
import qualified Data.Text                         as T
import           Data.Time.Clock
import           Data.Time.Clock.POSIX
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
authenticator c k uuid = do
  currentTime      <- liftIO getCurrentTime
  encryptionResult <- liftIO (encryptJwt ec k $ claims currentTime)
  handleEncryptionResult currentTime cc encryptionResult
  where ec          = encryptionConfig c
        cc          = cookieConfig c
        claims time = mkClaims (applicationName c) (U.toText uuid) time cc

authenticationGuard :: AuthenticationConfig -> EncryptionKey -> ActionM UUID
authenticationGuard c k =
  maybe denyAccess authenticate =<< getJwtFromRequest cconfig <$> request
  where cconfig          = cookieConfig c
        authenticate jwt = liftIO (decryptJwt k jwt) >>= handleDecryptionResult c

denyAccess :: ActionM a
denyAccess = status status403 >> finish

handleEncryptionResult :: UTCTime -> CookieConfig -> Either JwtError Jwt -> ActionM ()
handleEncryptionResult _ c (Left err)  = logJwtError err >> status status403
handleEncryptionResult t c (Right jwt)
  | cookieDisabled c = setJSONResponse jwt
  | otherwise        = setCookie $ mkCookie c t jwt

handleDecryptionResult :: AuthenticationConfig -> Either JwtError JwtContent -> ActionM UUID
handleDecryptionResult c (Left err) = logJwtError err >> denyAccess
handleDecryptionResult c (Right j)  = liftIO getCurrentTime >>= \t -> handleClaims t j
  where handleClaims t (Jwe (_, bs)) = maybe denyAccess return $ uuidFromClaims t bs
        handleClaims _ _             = unexpectedJwtFormat
        uuidFromClaims t bs = do
          claims <- A.decode $ BS.fromStrict bs
          valid  <- validateClaims t claims
          if valid then extractUUID claims else Nothing
        validateClaims currentTime claims = fmap (== applicationName c) (jwtIss claims) `mplus`
                                            fmap ((> currentTime) . posixSecondsToUTCTime . unwrapIntDate) (jwtExp claims)
        extractUUID                       = join . fmap U.fromText . jwtSub
        unwrapIntDate (IntDate d) = d

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

-- Get the JWT for the app out of the cookie request headers OR
-- get it from the Authorization header
getJwtFromRequest :: CookieConfig -> Request -> Maybe Jwt
getJwtFromRequest c r = getJwtFromCookie r <|> getJwtFromAuthorization r
  where name = cookieName c
        getJwtFromCookie = join                .
                           fmap (fmap Jwt    .
                                 lookup name .
                                 parseCookies) .
                           lookup hCookie      .
                           requestHeaders
        getJwtFromAuthorization = join                     .
                           fmap (fmap Jwt .
                                 B.stripPrefix "Bearer ")  .
                           lookup hAuthorization           .
                           requestHeaders

mkCookie :: CookieConfig -> UTCTime -> Jwt -> SetCookie
mkCookie c t (Jwt j) = def {
    setCookieName     = cookieName c
  , setCookieValue    = j
  , setCookieHttpOnly = True
  , setCookiePath     = Just $ cookiePath c
  , setCookieExpires  = Just $ expirationTime t c
  }

setJSONResponse :: Jwt -> ActionM ()
setJSONResponse (Jwt j) = raw (BS.fromStrict quoted) >> setHeader "Content-Type" "application/json; charset=utf8"
  where quoted = "\"" `B.append` j `B.append` "\""

expirationTime :: UTCTime -> CookieConfig -> UTCTime
expirationTime t c = secondsForExpiration (cookieExpiration c) `addUTCTime` t

mkClaims :: T.Text -> T.Text -> UTCTime -> CookieConfig -> AppClaims
mkClaims iss sub t cc = AC . Claims . BS.toStrict $ A.encode JwtClaims {
    jwtIss = Just iss
  , jwtSub = Just sub
  , jwtAud = Nothing
  , jwtExp = Just . IntDate . utcTimeToPOSIXSeconds $ expirationTime t cc
  , jwtNbf = Nothing
  , jwtIat = Nothing
  , jwtJti = Nothing
  }
