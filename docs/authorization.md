# Authorization

Authorization answers one question: can this security context perform this permission against this optional resource?

## Authorizer

`Authorizer` checks matching policies first and falls back to permissions already present in the context.

```php
$result = $authorizer->decide($context, 'posts.update', $post);
```

The result is an `AuthorizationResult`.

## Decisions

`AuthorizationResult` wraps an `AccessDecision`.

- `Allow` means the action is granted.
- `Deny` means the action is rejected.
- `Abstain` means a policy intentionally did not decide.

The authorizer treats final abstention as denial unless the context permission fallback grants the permission.

## Denial Precedence

When multiple policies support a permission, a denial wins immediately. This keeps explicit safety decisions from being overwritten by a later grant.

## Convenience Methods

```php
$authorizer->can($context, 'billing.view');
$authorizer->cannot($context, 'billing.delete');
$authorizer->authorize($context, 'billing.update');
```

`authorize()` returns the granted result or throws `AccessDeniedException`.

## Result Objects

Results can carry context:

```php
AuthorizationResult::deny(
    reason: 'Only owners can delete this post.',
    permission: 'posts.delete',
    resource: $post,
    policy: 'post-owner',
);
```

Use result objects when callers need reason text, policy names, or resource-aware reporting.
