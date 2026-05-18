# Getting Started

CommonPHP Security provides small security services that application layers can compose directly.

## Install

```bash
composer require comphp/security
```

In this monorepo, the package is available through the workspace path repository and the root Composer autoloader.

## Create A Security Context

```php
<?php

declare(strict_types=1);

use CommonPHP\Security\Role;
use CommonPHP\Security\SecurityContext;

$editor = new Role('editor', [
    'posts.view',
    'posts.update',
]);

$context = SecurityContext::forIdentity(
    identity: ['id' => 42, 'email' => 'ada@example.com'],
    roles: [$editor],
    permissions: ['posts.create'],
    attributes: ['tenant' => 'acme'],
);
```

The context is a simple snapshot of the current actor, roles, direct permissions, and caller-defined attributes.

## Authorize A Permission

```php
use CommonPHP\Security\Authorizer;

$authorizer = new Authorizer();

if ($authorizer->can($context, 'posts.update')) {
    // Continue with the protected operation.
}
```

Use `authorize()` when a denial should throw `AccessDeniedException`.

## Protect Forms With CSRF Tokens

```php
use CommonPHP\Security\CsrfTokenManager;
use CommonPHP\Security\SessionCsrfTokenStorage;

$manager = new CsrfTokenManager(new SessionCsrfTokenStorage($session));
$token = $manager->getToken('profile.update');

echo '<input type="hidden" name="_token" value="' . htmlspecialchars($token->value(), ENT_QUOTES) . '">';
```

Validate the submitted value with `validateToken()` or `isTokenValid()`.

## Hash Passwords

```php
use CommonPHP\Security\NativePasswordHasher;

$hasher = new NativePasswordHasher();
$hash = $hasher->hash($plainPassword);

if ($hasher->verify($plainPassword, $hash) && $hasher->needsRehash($hash)) {
    $hash = $hasher->hash($plainPassword);
}
```
