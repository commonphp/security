# Basic Authorization

```php
<?php

declare(strict_types=1);

use CommonPHP\Security\Authorizer;
use CommonPHP\Security\Role;
use CommonPHP\Security\SecurityContext;

$editor = new Role('editor', ['posts.view', 'posts.update']);
$context = SecurityContext::forIdentity($user, roles: [$editor]);
$authorizer = new Authorizer();

if ($authorizer->can($context, 'posts.update')) {
    // Update the post.
}
```

Use direct context grants for simple permission checks that do not need resource-specific policy logic.
