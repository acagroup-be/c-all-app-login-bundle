# C-all App Login Bundle

Symfony bundle that authenticates users of a C-all application through the C-all login app (OAuth 2.0 authorization code + OpenID Connect id_token).

Requires PHP 8.2+ and Symfony 6.4 or 7.x. Version 1.x targeted Symfony 5.4/6.0 and PHP 8.1, see [Upgrading](#upgrading-from-1x).

## Installation

```
composer require vbridgecloud/c-all-app-login-bundle:^2.0
```

Register the bundle:

```php
# config/bundles.php
return [
    // ...
    vBridgeCloud\CallLoginBundle\CallLoginBundle::class => ['all' => true],
];
```

Configure it:

```yaml
# config/packages/call_login.yaml
call_login:
  public_url: '%env(LOGIN_PUBLIC_URL)%'       # public URL of the login app, the browser is redirected here
  internal_url: '%env(LOGIN_INTERNAL_URL)%'   # URL this app uses to reach the login app server-to-server
  client_id: '%env(LOGIN_CLIENT_ID)%'
  client_secret: '%env(LOGIN_CLIENT_SECRET)%'
  public_key: '%env(LOGIN_PUBLIC_KEY)%'       # RSA public key of the login app, see below
  # login_redirect_path: home                 # route to land on after login when no state is present
  # oauth_redirect_path: call_login_authorize # route the login app redirects back to
```

`public_key` accepts the PEM contents, a file path, or a `file://` URI. It is the `public.key` the login app signs its tokens with (the counterpart of its `private.key`). Every id_token is checked against it: RS256 signature, `aud` equal to `client_id`, and the validity window with 60 seconds of leeway. Tokens that fail are refused and the user is sent back to the login page.

Wire it into the security configuration:

```yaml
# config/packages/security.yaml
security:
    providers:
        call_login:
            id: call_login.user_provider
    firewalls:
        main:
            provider: call_login
            custom_authenticators:
                - call_login.authenticator
            entry_point: call_login.entrypoint
    access_control:
        - { path: ^/login/authorize, roles: PUBLIC_ACCESS }
```

### Redirect endpoint

The login app redirects back to a route of this application. Either import the bundled route:

```yaml
# config/routes/call_login.yaml
call_login:
  resource: '@CallLoginBundle/Resources/config/routing.yaml'
```

or point `oauth_redirect_path` at a route of your own. The route only needs to exist, the authenticator handles the request before any controller runs.

## How it works

1. An unauthenticated request hits the entry point, which redirects to `{public_url}/authorize` with the originating route in `state`.
2. The login app redirects back with a `code` (or, when it still holds a valid token for this client, with `access_token` and `id_token` directly).
3. `JwtAuthenticator` exchanges the code at `{internal_url}/access_token`, verifies the id_token with `public_key`, stores the access token in the session and builds an `AuthenticatedUser` from the id_token claims (`id`, `company_id`, `name`, `email`, `roles`).
4. On every following request `UserProvider::refreshUser()` re-validates the stored access token at `{internal_url}/api/token/verify`.

## Upgrading from 1.x

- PHP 8.2+, Symfony 6.4 or 7.x, lcobucci/jwt 5.
- New required option `public_key`, the login app's public key. id_tokens are verified against it (signature, audience, validity), so the container will not compile without it.
- `AuthenticatedUser::getUsername()`, `getSalt()` and `UserProvider::loadUserByUsername()` are gone (they left the Symfony interfaces in 6.0). Use `getUserIdentifier()` / `getName()`.
- The configuration root is `call_login` (it always was, the tree name used to say `vbridgecloud_calllogin`).

## Development

```
composer install
composer test
composer phpstan
```
