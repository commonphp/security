# CommonPHP Security Documentation

CommonPHP Security is the standalone security package for CommonPHP applications and plain PHP projects. It provides authorization decisions, policies, role and permission helpers, security context objects, password hashing, and CSRF token management.

Security is intentionally explicit. Expected authorization denials can be represented as `AuthorizationResult` objects, while invalid configuration, malformed CSRF state, and failed assertions throw package-specific exceptions.

## Start Here

- [Getting started](getting-started.md)
- [Usage](usage.md)
- [Package boundaries](package-boundaries.md)

## Security Concepts

- [Security context](security-context.md)
- [Authorization](authorization.md)
- [Policies](policies.md)
- [CSRF protection](csrf.md)
- [Password hashing](passwords.md)
- [Error handling](error-handling.md)

## Examples

- [Examples index](examples/index.md)
- [Basic authorization](examples/basic-authorization.md)
- [Custom policy](examples/custom-policy.md)
- [CSRF form token](examples/csrf-form-token.md)
- [Password hashing](examples/password-hashing.md)

## Development

- [Testing and QA](testing.md)

## Public API Map

Entry points:

- `CommonPHP\Security\Authorizer`
- `CommonPHP\Security\PolicyRegistry`
- `CommonPHP\Security\SecurityContext`
- `CommonPHP\Security\CsrfTokenManager`
- `CommonPHP\Security\SessionCsrfTokenStorage`
- `CommonPHP\Security\NativePasswordHasher`

Authorization objects:

- `CommonPHP\Security\AuthorizationResult`
- `CommonPHP\Security\Permission`
- `CommonPHP\Security\Role`
- `CommonPHP\Security\Enums\AccessDecision`

CSRF objects:

- `CommonPHP\Security\CsrfToken`

Contracts:

- `CommonPHP\Security\Contracts\AuthorizerInterface`
- `CommonPHP\Security\Contracts\PolicyInterface`
- `CommonPHP\Security\Contracts\SecurityContextInterface`
- `CommonPHP\Security\Contracts\CsrfTokenManagerInterface`
- `CommonPHP\Security\Contracts\CsrfTokenStorageInterface`
- `CommonPHP\Security\Contracts\PasswordHasherInterface`

Exceptions:

- `CommonPHP\Security\Exceptions\SecurityException`
- `CommonPHP\Security\Exceptions\AuthorizationException`
- `CommonPHP\Security\Exceptions\AccessDeniedException`
- `CommonPHP\Security\Exceptions\InvalidCsrfTokenException`
- `CommonPHP\Security\Exceptions\PasswordHashException`
- `CommonPHP\Security\Exceptions\PolicyNotFoundException`
