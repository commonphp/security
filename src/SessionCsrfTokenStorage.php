<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use CommonPHP\Security\Contracts\CsrfTokenStorageInterface;
use CommonPHP\Security\Exceptions\InvalidCsrfTokenException;
use CommonPHP\Session\Contracts\SessionBagInterface;
use CommonPHP\Session\Contracts\SessionInterface;

final class SessionCsrfTokenStorage implements CsrfTokenStorageInterface
{
    public const string DEFAULT_NAMESPACE = '_csrf_tokens';

    public function __construct(
        private readonly SessionInterface|SessionBagInterface $session,
        private readonly string $namespace = self::DEFAULT_NAMESPACE,
    ) {
        CsrfToken::normalizeId($namespace);
    }

    public function get(string $id): ?CsrfToken
    {
        $id = CsrfToken::normalizeId($id);
        $entry = $this->bag()->get($id);

        if ($entry === null) {
            return null;
        }

        return $this->hydrate($id, $entry);
    }

    public function put(CsrfToken $token): static
    {
        $this->bag()->set($token->id(), $token->toArray());

        return $this;
    }

    public function remove(string $id): static
    {
        $this->bag()->remove(CsrfToken::normalizeId($id));

        return $this;
    }

    public function has(string $id): bool
    {
        return $this->get($id) !== null;
    }

    /**
     * @return array<string, CsrfToken>
     */
    public function all(): array
    {
        $tokens = [];

        foreach ($this->bag()->all() as $id => $entry) {
            $tokens[(string) $id] = $this->hydrate((string) $id, $entry);
        }

        return $tokens;
    }

    public function clear(): static
    {
        $this->bag()->clear();

        return $this;
    }

    private function bag(): SessionBagInterface
    {
        if ($this->session instanceof SessionBagInterface) {
            return $this->session;
        }

        return $this->session->bag($this->namespace);
    }

    private function hydrate(string $id, mixed $entry): CsrfToken
    {
        if ($entry instanceof CsrfToken) {
            return $entry;
        }

        if (is_array($entry)) {
            return CsrfToken::fromArray($entry);
        }

        if (is_string($entry)) {
            return new CsrfToken($id, $entry);
        }

        throw InvalidCsrfTokenException::malformed($id);
    }
}
