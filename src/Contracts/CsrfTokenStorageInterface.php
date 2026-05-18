<?php

declare(strict_types=1);

namespace CommonPHP\Security\Contracts;

use CommonPHP\Security\CsrfToken;

interface CsrfTokenStorageInterface
{
    public function get(string $id): ?CsrfToken;

    public function put(CsrfToken $token): static;

    public function remove(string $id): static;

    public function has(string $id): bool;

    /**
     * @return array<string, CsrfToken>
     */
    public function all(): array;

    public function clear(): static;
}
