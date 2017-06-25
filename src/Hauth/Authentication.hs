{-# LANGUAGE OverloadedStrings #-}

module Hauth.Authentication where

import qualified Data.ByteString    as BS
import           Data.Default.Class
import qualified Data.Text          as T
import           Jose.Jwa

data CookieExpiration = OneHour
                      | OneDay
                      | OneWeek
                      | Persistent
                      | Other Int

data EncryptionConfig = EncryptionConfig {
    algorithm  :: JweAlg
  , encryption :: Enc
  , keyLen     :: Int
  , keyId      :: T.Text
  }

instance Default EncryptionConfig where
  def = EncryptionConfig {
      algorithm   = A256KW
    , encryption  = A256GCM
    , keyLen      = 32
    , keyId       = ""
    }

data CookieConfig = CookieConfig {
    cookieName       :: BS.ByteString
  , cookieExpiration :: CookieExpiration
  , cookiePath       :: BS.ByteString
  }

instance Default CookieConfig where
  def = CookieConfig {
      cookieName       = "CHANGE-ME"
    , cookieExpiration = OneDay
    , cookiePath       = "/"
    }

data AuthenticationConfig = AuthenticationConfig {
    applicationName  :: T.Text
  , logging          :: Bool
  , encryptionConfig :: EncryptionConfig
  , cookieConfig     :: CookieConfig
  }

instance Default AuthenticationConfig where
  def = AuthenticationConfig {
      applicationName   = "YOUR APPLICATION NAME HERE"
    , logging           = True
    , encryptionConfig  = def
    , cookieConfig      = def
    }

mkConfigWithAppAndCookieName :: T.Text -> BS.ByteString -> AuthenticationConfig
mkConfigWithAppAndCookieName appName cookieName = def {
    applicationName = "FlowAppAPI"
  , cookieConfig = def {
      cookieName = "FlowAppAPICookie"
    }
  }
