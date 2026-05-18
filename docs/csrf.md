# CSRF Protection

CommonPHP Security provides token value objects, a token manager, and a storage contract for CSRF protection.

## Token Object

`CsrfToken` contains:

- an id, such as `profile.update`;
- a generated value;
- a creation time.

Token ids are trimmed and may contain letters, numbers, dots, underscores, colons, and hyphens.

## Token Manager

`CsrfTokenManager` creates, caches, refreshes, validates, and removes tokens.

```php
$token = $manager->getToken('checkout.submit');
```

`getToken()` returns an existing non-expired token or creates a new one. `refreshToken()` always creates a new value.

## Validation

```php
$manager->validateToken('checkout.submit', $submittedValue);
```

`validateToken()` returns the stored token or throws `InvalidCsrfTokenException`. `isTokenValid()` returns a boolean and catches expected CSRF validation failures.

Set `consume: true` for one-time token use.

```php
$manager->validateToken('checkout.submit', $submittedValue, consume: true);
```

## Storage

`SessionCsrfTokenStorage` stores token arrays in a CommonPHP session bag.

```php
use CommonPHP\Security\SessionCsrfTokenStorage;

$storage = new SessionCsrfTokenStorage($session, '_csrf_tokens');
```

The storage also accepts a `SessionBagInterface`, which is useful for tests and alternate integrations.

## Expiration

Pass a `DateInterval` to the manager to expire old tokens.

```php
$manager = new CsrfTokenManager($storage, ttl: new DateInterval('PT30M'));
```

Expired tokens are removed when checked or validated.
