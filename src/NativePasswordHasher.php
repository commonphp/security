<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use CommonPHP\Security\Contracts\PasswordHasherInterface;
use CommonPHP\Security\Exceptions\PasswordHashException;
use Throwable;
use ValueError;

final readonly class NativePasswordHasher implements PasswordHasherInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function __construct(
        private string|int|null $algorithm = PASSWORD_DEFAULT,
        private array $options = [],
    ) {
    }

    public function hash(string $plainPassword): string
    {
        try {
            $hash = password_hash($plainPassword, $this->algorithm, $this->options);
        } catch (ValueError $exception) {
            throw PasswordHashException::forHashing($exception);
        } catch (Throwable $throwable) {
            throw PasswordHashException::forHashing($throwable);
        }

        if (!is_string($hash) || $hash === '') {
            throw PasswordHashException::forHashing();
        }

        return $hash;
    }

    public function verify(string $plainPassword, string $hash): bool
    {
        if ($hash === '') {
            return false;
        }

        return password_verify($plainPassword, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        try {
            return password_needs_rehash($hash, $this->algorithm, $this->options);
        } catch (ValueError $exception) {
            throw PasswordHashException::forRehashCheck($exception);
        } catch (Throwable $throwable) {
            throw PasswordHashException::forRehashCheck($throwable);
        }
    }

    public function algorithm(): string|int|null
    {
        return $this->algorithm;
    }

    /**
     * @return array<string, mixed>
     */
    public function options(): array
    {
        return $this->options;
    }
}
