<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Fixtures;

use CommonPHP\Security\Contracts\CsrfTokenStorageInterface;
use CommonPHP\Security\CsrfToken;

final class MemoryCsrfTokenStorage implements CsrfTokenStorageInterface
{
    /**
     * @var array<string, CsrfToken>
     */
    private array $tokens = [];

    /**
     * @param iterable<CsrfToken> $tokens
     */
    public function __construct(iterable $tokens = [])
    {
        foreach ($tokens as $token) {
            $this->put($token);
        }
    }

    public function get(string $id): ?CsrfToken
    {
        return $this->tokens[CsrfToken::normalizeId($id)] ?? null;
    }

    public function put(CsrfToken $token): static
    {
        $this->tokens[$token->id()] = $token;

        return $this;
    }

    public function remove(string $id): static
    {
        unset($this->tokens[CsrfToken::normalizeId($id)]);

        return $this;
    }

    public function has(string $id): bool
    {
        return isset($this->tokens[CsrfToken::normalizeId($id)]);
    }

    public function all(): array
    {
        return $this->tokens;
    }

    public function clear(): static
    {
        $this->tokens = [];

        return $this;
    }
}
