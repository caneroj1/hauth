module Hauth.Authentication.CookieHelper where

import           Data.Time.Clock      (NominalDiffTime)
import           Hauth.Authentication

secondsForExpiration :: CookieExpiration -> NominalDiffTime
secondsForExpiration OneHour    = 3600
secondsForExpiration OneDay     = 86400
secondsForExpiration OneWeek    = 604800
secondsForExpiration Persistent = 946100000 -- 30 years
secondsForExpiration (Other i)  = fromIntegral i
