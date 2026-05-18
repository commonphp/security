# CSRF Form Token

```php
<?php

declare(strict_types=1);

use CommonPHP\Security\CsrfTokenManager;
use CommonPHP\Security\SessionCsrfTokenStorage;

$csrf = new CsrfTokenManager(new SessionCsrfTokenStorage($session));
$token = $csrf->getToken('account.email');
```

Render the token value into a hidden field.

```php
<input type="hidden" name="_token" value="<?= htmlspecialchars($token->value(), ENT_QUOTES) ?>">
```

Validate on submission.

```php
if (!$csrf->isTokenValid('account.email', $_POST['_token'] ?? '', consume: true)) {
    // Reject the request.
}
```
