# Password Hashing

```php
<?php

declare(strict_types=1);

use CommonPHP\Security\NativePasswordHasher;

$hasher = new NativePasswordHasher();
$hash = $hasher->hash($newPassword);

if ($hasher->verify($submittedPassword, $hash)) {
    if ($hasher->needsRehash($hash)) {
        $hash = $hasher->hash($submittedPassword);
    }
}
```
