{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Control.Monad.IO.Class
import           Data.Monoid
import           Data.Text                            (Text)
import qualified Data.Text.Lazy                       as T
import           Data.UUID
import           Data.UUID.V4
import           Hauth
import           Network.Wai
import           Network.Wai.Middleware.RequestLogger
import           Web.Scotty

authenticationConfig :: AuthenticationConfig
authenticationConfig = mkConfigWithAppAndCookieName "TestAppAPI" "TestAppAPICookie"

disableCookies :: AuthenticationConfig -> AuthenticationConfig
disableCookies ac = ac { cookieConfig = (cookieConfig ac) { cookieDisabled = True } }

main :: IO ()
main = do
  (authGuard, authenticator) <- buildAuthenticatorPair $ disableCookies authenticationConfig
  scotty 3000 $ do
    middleware logStdoutDev
    get "/" $ do
      uuid <- authGuard
      text ("Successfully authenticated: " `T.append` T.fromStrict (toText uuid))
    post "/v1/authenticate" $ do
      uuid <- liftIO nextRandom
      authenticator uuid
