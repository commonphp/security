# Security Context

`SecurityContext` carries the actor and grants for one authorization operation or request.

## Identity

The identity may be any application value:

- an authenticated user object;
- an array from an authentication package;
- a scalar account id;
- `null` for guests.

`SecurityContext::forIdentity()` marks the context authenticated. `SecurityContext::guest()` marks it unauthenticated.

## Roles

Roles group permissions.

```php
use CommonPHP\Security\Role;

$admin = new Role('admin', [
    'users.read',
    'users.create',
    'users.delete',
]);
```

Role names are normalized by trimming whitespace. They may contain letters, numbers, dots, underscores, colons, and hyphens.

## Permissions

Permissions are normalized value objects.

```php
use CommonPHP\Security\Permission;

$permission = new Permission('posts.publish');
```

Permission names follow the same character rules as roles and may be up to 128 bytes.

## Direct Permissions

Direct permissions are grants assigned to the context outside of roles.

```php
$context->grant('reports.export');
```

`permissions()` returns the union of direct permissions and role permissions. `directPermissions()` returns only direct grants.

## Attributes

Attributes are caller-defined values that policies can use.

```php
$context->setAttribute('tenant_id', 1001);
```

Security does not interpret attributes. Application and policy code decide what they mean.
