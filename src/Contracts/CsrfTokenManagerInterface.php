<?php

declare(strict_types=1);

namespace CommonPHP\Security\Contracts;

use CommonPHP\Security\CsrfToken;

interface CsrfTokenManagerInterface
{
    public const string DEFAULT_TOKEN_ID = '_token';

    public function getToken(string $id = self::DEFAULT_TOKEN_ID): CsrfToken;

    public function refreshToken(string $id = self::DEFAULT_TOKEN_ID): CsrfToken;

    public function hasToken(string $id = self::DEFAULT_TOKEN_ID): bool;

    public function validateToken(string $id, string $value, bool $consume = false): CsrfToken;

    public function isTokenValid(string $id, string $value, bool $consume = false): bool;

    public function removeToken(string $id = self::DEFAULT_TOKEN_ID): static;
}
