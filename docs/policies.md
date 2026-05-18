# Policies

Policies are small classes that decide resource-aware permissions.

## Contract

A policy implements `PolicyInterface`.

```php
use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Contracts\PolicyInterface;
use CommonPHP\Security\Contracts\SecurityContextInterface;
use CommonPHP\Security\Permission;

final class BillingPolicy implements PolicyInterface
{
    public function name(): string
    {
        return 'billing';
    }

    public function supports(Permission|string $permission, mixed $resource = null): bool
    {
        return Permission::from($permission)->equals('billing.view');
    }

    public function decide(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult|bool {
        return $context->hasRole('billing-admin')
            ? AuthorizationResult::allow()
            : AuthorizationResult::deny('Billing admins only.');
    }
}
```

## Registry

`PolicyRegistry` stores named policies.

```php
$registry = new PolicyRegistry([$billingPolicy]);
$registry->add($postPolicy);
```

Names default to `PolicyInterface::name()` but can be overridden when adding a policy.

## Matching

`matching()` returns policies whose `supports()` method accepts the permission and resource.

```php
$policies = $registry->matching('posts.update', $post);
```

The authorizer uses this same matching behavior during decisions.

## Return Values

Policies may return:

- `AuthorizationResult`
- `AccessDecision`
- `bool`

Use `AuthorizationResult` when the caller should see a reason or policy-specific metadata.
