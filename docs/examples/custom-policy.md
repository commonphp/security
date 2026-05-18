# Custom Policy

```php
<?php

declare(strict_types=1);

use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Contracts\PolicyInterface;
use CommonPHP\Security\Contracts\SecurityContextInterface;
use CommonPHP\Security\Permission;

final class OwnsPostPolicy implements PolicyInterface
{
    public function name(): string
    {
        return 'owns-post';
    }

    public function supports(Permission|string $permission, mixed $resource = null): bool
    {
        return Permission::from($permission)->equals('posts.delete')
            && is_array($resource)
            && isset($resource['owner_id']);
    }

    public function decide(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult {
        return $context->attribute('user_id') === $resource['owner_id']
            ? AuthorizationResult::allow('The current user owns this post.')
            : AuthorizationResult::deny('Only the owner can delete this post.');
    }
}
```
