# Usage

The package has four common usage styles: direct permission checks, policy-backed authorization, session-backed CSRF protection, and native password hashing.

## Direct Permission Checks

Direct checks use roles and permissions already present in a `SecurityContext`.

```php
use CommonPHP\Security\Authorizer;
use CommonPHP\Security\SecurityContext;

$context = new SecurityContext(
    identity: $user,
    roles: [$editorRole],
    permissions: ['media.upload'],
);

$allowed = (new Authorizer())->can($context, 'media.upload');
```

Role permissions and direct permissions are both considered. Direct permissions are useful for grants that do not belong to a reusable role.

## Policy-Backed Checks

Policies are useful when a decision depends on a resource.

```php
use CommonPHP\Security\Authorizer;
use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Contracts\PolicyInterface;
use CommonPHP\Security\Contracts\SecurityContextInterface;
use CommonPHP\Security\Permission;
use CommonPHP\Security\PolicyRegistry;

final class PostOwnerPolicy implements PolicyInterface
{
    public function name(): string
    {
        return 'post-owner';
    }

    public function supports(Permission|string $permission, mixed $resource = null): bool
    {
        return Permission::from($permission)->equals('posts.update')
            && is_array($resource)
            && array_key_exists('owner_id', $resource);
    }

    public function decide(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult {
        return $context->attribute('user_id') === $resource['owner_id']
            ? AuthorizationResult::allow('The actor owns this post.')
            : AuthorizationResult::deny('Only the owner can update this post.');
    }
}

$authorizer = new Authorizer(new PolicyRegistry([new PostOwnerPolicy()]));
$result = $authorizer->decide($context, 'posts.update', $post);
```

Policies are evaluated before the context permission fallback. Any matching policy may grant access, but a denial wins immediately.

## CSRF Token Flow

```php
$token = $csrf->getToken('billing.card.update');

if (!$csrf->isTokenValid('billing.card.update', $_POST['_token'] ?? '', consume: true)) {
    // Reject the request.
}
```

Set `consume: true` for one-time token validation.

## Password Flow

```php
$hash = $hasher->hash($password);

if (!$hasher->verify($submittedPassword, $hash)) {
    // Reject login.
}
```

`NativePasswordHasher` wraps PHP's password API and converts hashing configuration errors into `PasswordHashException`.
