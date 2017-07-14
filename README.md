# hauth

## Notes

Most definitely not production ready. There are a few things that still need to happen _if_ this will ever make it there.

* Create the encryption key in a place where it can be retrieved. Currently, a new encryption key is created whenever the application is started.
* Maybe integrate with other user-management systems in haskell?
* Maybe store each jwt in a db where they can be attached to user IDs so they can be expired.
* Use lens for managementing configuration state?
* Extend the authentication to support other application-specific claims?
* More?

## Usage

```haskell

-- Basic authentication config for the application.
authenticationConfig :: AuthenticationConfig
authenticationConfig = mkConfigWithAppAndCookieName "TestAppAPI" ""

-- We don't want to allow cookie-based authentication.
-- The app will now expect jwt tokens in the Authorization header as "Bearer <jwt>"
disableCookies :: AuthenticationConfig -> AuthenticationConfig
disableCookies ac = ac { cookieConfig = (cookieConfig ac) { cookieDisabled = True } }

-- Start the app
----------------
-- 1.
-- With our configuration settings, build the authentication machinery for the
-- application. This returns a tuple of functions.
-- The first function is the authentication guard and can be used to secure
-- routes. It returns a UUID if all authentication is successful.
----------------
-- 2.
-- Use the `authGuard` function to guard this route. It will look for a jwt,-- decode it, make sure it is valid and not expired, and return the UUID
--from the token.
----------------
-- 3.
-- Use the `authenticator` function to authenticate a "user" and return a
-- jwt. The `authenticator` accepts a UUID, so presumably this happens after
-- username/password authentication gets the UUID. The jwt returned from the
-- `authenticator` will be checked in the `authGuard`.
main :: IO ()
main = do
  -- 1.
  (authGuard, authenticator) <- buildAuthenticatorPair $ disableCookies authenticationConfig
  scotty 3000 $ do
    middleware logStdoutDev
    get "/" $ do
      -- 2.
      uuid <- authGuard
      text ("Successfully authenticated: " `T.append` T.fromStrict (toText uuid))
    post "/v1/authenticate" $ do
      uuid <- liftIO nextRandom
      -- 3
      authenticator uuid


```