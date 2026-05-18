# Error Handling

Security separates expected denials from broken security state.

## Authorization Results

Use `AuthorizationResult` when a denied permission is normal application flow.

```php
$result = $authorizer->decide($context, 'reports.export');

if ($result->isDenied()) {
    return $result->reason();
}
```

## Access Denied Exceptions

Use `authorize()` when the caller prefers exceptions.

```php
$authorizer->authorize($context, 'reports.export');
```

Denied access throws `AccessDeniedException`.

## CSRF Exceptions

`InvalidCsrfTokenException` covers:

- invalid token ids or values;
- missing tokens;
- mismatched submitted values;
- expired tokens;
- malformed stored token state;
- invalid token generator configuration.

## Password Exceptions

`PasswordHashException` wraps hashing and rehash-check configuration failures.

Verification failures are not exceptional; `verify()` returns `false`.

## Registry Exceptions

`PolicyNotFoundException` is thrown when code asks for an unregistered policy by name.
