<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use CommonPHP\Security\Contracts\CsrfTokenManagerInterface;
use CommonPHP\Security\Contracts\CsrfTokenStorageInterface;
use CommonPHP\Security\Exceptions\InvalidCsrfTokenException;
use DateInterval;
use Random\RandomException;

final class CsrfTokenManager implements CsrfTokenManagerInterface
{
    public const string DEFAULT_TOKEN_ID = CsrfTokenManagerInterface::DEFAULT_TOKEN_ID;

    public function __construct(
        private readonly CsrfTokenStorageInterface $storage,
        private readonly int $bytes = 32,
        private readonly ?DateInterval $ttl = null,
    ) {
        if ($bytes < 16) {
            throw InvalidCsrfTokenException::invalidGeneratorConfig(
                'CSRF tokens require at least 16 random bytes.',
            );
        }
    }

    public function getToken(string $id = self::DEFAULT_TOKEN_ID): CsrfToken
    {
        $id = CsrfToken::normalizeId($id);
        $token = $this->storage->get($id);

        if ($token === null || $this->isExpired($token)) {
            if ($token !== null) {
                $this->storage->remove($id);
            }

            return $this->refreshToken($id);
        }

        return $token;
    }

    public function refreshToken(string $id = self::DEFAULT_TOKEN_ID): CsrfToken
    {
        $id = CsrfToken::normalizeId($id);

        try {
            $token = new CsrfToken($id, bin2hex(random_bytes($this->bytes)));
        } catch (RandomException $exception) {
            throw InvalidCsrfTokenException::generationFailed($exception);
        }

        $this->storage->put($token);

        return $token;
    }

    public function hasToken(string $id = self::DEFAULT_TOKEN_ID): bool
    {
        $id = CsrfToken::normalizeId($id);
        $token = $this->storage->get($id);

        if ($token === null) {
            return false;
        }

        if ($this->isExpired($token)) {
            $this->storage->remove($id);

            return false;
        }

        return true;
    }

    public function validateToken(string $id, string $value, bool $consume = false): CsrfToken
    {
        $id = CsrfToken::normalizeId($id);
        $token = $this->storage->get($id) ?? throw InvalidCsrfTokenException::missing($id);

        if ($this->isExpired($token)) {
            $this->storage->remove($id);

            throw InvalidCsrfTokenException::expired($id);
        }

        if (!$token->matches($value)) {
            throw InvalidCsrfTokenException::mismatch($id);
        }

        if ($consume) {
            $this->storage->remove($id);
        }

        return $token;
    }

    public function isTokenValid(string $id, string $value, bool $consume = false): bool
    {
        try {
            $this->validateToken($id, $value, $consume);

            return true;
        } catch (InvalidCsrfTokenException) {
            return false;
        }
    }

    public function removeToken(string $id = self::DEFAULT_TOKEN_ID): static
    {
        $this->storage->remove(CsrfToken::normalizeId($id));

        return $this;
    }

    private function isExpired(CsrfToken $token): bool
    {
        return $this->ttl !== null && $token->isExpired($this->ttl);
    }
}
