# Package Boundaries

CommonPHP Security owns reusable security helpers that sit around authentication and application surfaces.

## Belongs Here

- Permission and role value objects.
- Security context objects.
- Authorization result objects.
- Policy registration and evaluation.
- CSRF token objects, managers, and storage contracts.
- Password hashing contracts and native implementation.
- Security-specific exceptions.

## Does Not Belong Here

- Login forms or authentication flows.
- Identity providers, credential verification, or auth drivers.
- HTTP request parsing or response rendering.
- Session driver implementation.
- Database queries for permissions or identities.
- Runtime bootstrapping, service providers, modules, or container wiring.
- UI components for forms or error messages.

Those concerns should live in their own packages and call Security at the boundary.

## Integration Shape

Authentication packages should create or hydrate an identity, then build a `SecurityContext` with roles, permissions, and attributes.

HTTP or UI packages should render CSRF token values and translate `InvalidCsrfTokenException` or `AccessDeniedException` into their own response style.

Persistence packages may store role and permission assignments, but Security should continue to operate on plain value objects and contracts.
