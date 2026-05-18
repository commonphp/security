# Password Hashing

`NativePasswordHasher` wraps PHP's native password API behind `PasswordHasherInterface`.

## Hash

```php
$hasher = new NativePasswordHasher();
$hash = $hasher->hash($password);
```

By default the hasher uses `PASSWORD_DEFAULT`.

## Verify

```php
if (!$hasher->verify($submittedPassword, $storedHash)) {
    // Invalid credentials.
}
```

An empty stored hash returns `false`.

## Rehash

```php
if ($hasher->needsRehash($storedHash)) {
    $storedHash = $hasher->hash($submittedPassword);
}
```

Use this after successful verification to move old hashes to the current algorithm or options.

## Options

```php
$hasher = new NativePasswordHasher(PASSWORD_BCRYPT, ['cost' => 12]);
```

Invalid algorithms or option errors are wrapped in `PasswordHashException`.
