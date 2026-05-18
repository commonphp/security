# Testing And QA

The package test suite should cover every public class and contract behavior.

## Local Tests

From `package/security`:

```bash
..\..\vendor\bin\phpunit.bat
```

On Unix-like shells:

```bash
../../vendor/bin/phpunit
```

## What To Test

Security tests should verify:

- permission and role normalization;
- context authentication, grants, roles, attributes, and clone isolation;
- policy registry add, override, lookup, matching, removal, and clearing;
- authorization grant, deny, abstain, and denial precedence;
- result object metadata and exception behavior;
- CSRF token creation, serialization, matching, expiration, malformed state, validation, consumption, and storage;
- password hash, verify, rehash, and invalid configuration handling;
- exception factory messages and previous exceptions.

## Test Doubles

Use small fixtures for policies, token storage, and session behavior. Tests should avoid real PHP sessions unless specifically testing the native session package.

## Expected Failure Style

Expected denials should usually assert `AuthorizationResult` state. Broken configuration and invalid security state should assert package-specific exceptions.
