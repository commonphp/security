<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Fixtures;

use CommonPHP\Session\Contracts\FlashBagInterface;
use CommonPHP\Session\Contracts\SessionBagInterface;
use CommonPHP\Session\Contracts\SessionInterface;
use CommonPHP\Session\Enums\SessionStatus;
use CommonPHP\Session\FlashBag;
use CommonPHP\Session\SessionBag;

final class ArrayBackedSession implements SessionInterface
{
    /**
     * @var array<string, mixed>
     */
    private array $data;

    /**
     * @var array<string, SessionBagInterface>
     */
    private array $bags = [];

    /**
     * @var array<string, FlashBagInterface>
     */
    private array $flashBags = [];

    private ?SessionBagInterface $rootBag = null;

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        array $data = [],
        private bool $started = true,
        private string $sessionId = 'array-session-id',
        private string $sessionName = 'ARRAYSESSID',
    ) {
        $this->data = $data;
    }

    public function start(): static
    {
        $this->started = true;

        return $this;
    }

    public function save(): static
    {
        $this->started = false;

        return $this;
    }

    public function invalidate(): static
    {
        $this->data = [];
        $this->started = false;
        $this->resetBags();

        return $this;
    }

    public function regenerateId(bool $deleteOldSession = true): string
    {
        $this->sessionId .= '-regenerated';

        return $this->sessionId;
    }

    public function status(): SessionStatus
    {
        return $this->started ? SessionStatus::Active : SessionStatus::None;
    }

    public function isStarted(): bool
    {
        return $this->started;
    }

    public function id(): string
    {
        return $this->sessionId;
    }

    public function setId(string $id): static
    {
        $this->sessionId = $id;

        return $this;
    }

    public function name(): string
    {
        return $this->sessionName;
    }

    public function setName(string $name): static
    {
        $this->sessionName = $name;

        return $this;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->data) ? $this->data[$key] : $default;
    }

    public function set(string $key, mixed $value): static
    {
        $this->data[$key] = $value;
        $this->dropCachedNamespace($key);

        return $this;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function remove(string $key, mixed $default = null): mixed
    {
        if (!array_key_exists($key, $this->data)) {
            return $default;
        }

        $value = $this->data[$key];
        unset($this->data[$key]);
        $this->dropCachedNamespace($key);

        return $value;
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        return $this->remove($key, $default);
    }

    public function replace(array $values): static
    {
        $this->data = $values;
        $this->resetBags();

        return $this;
    }

    public function all(): array
    {
        return $this->data;
    }

    public function clear(): static
    {
        $this->data = [];
        $this->resetBags();

        return $this;
    }

    public function bag(?string $name = null): SessionBagInterface
    {
        if ($name === null) {
            if ($this->rootBag === null) {
                $data = &$this->data;
                $this->rootBag = new SessionBag($data, 'root');
            }

            return $this->rootBag;
        }

        $data = &$this->namespace($name);
        $this->bags[$name] ??= new SessionBag($data, $name);

        return $this->bags[$name];
    }

    public function flash(string $namespace = '_flash'): FlashBagInterface
    {
        $data = &$this->namespace($namespace);
        $this->flashBags[$namespace] ??= new FlashBag($data, $namespace);

        return $this->flashBags[$namespace];
    }

    /**
     * @return array<string, mixed>
     */
    private function &namespace(string $name): array
    {
        if (!array_key_exists($name, $this->data) || !is_array($this->data[$name])) {
            $this->data[$name] = [];
        }

        $namespace = &$this->data[$name];

        return $namespace;
    }

    private function resetBags(): void
    {
        $this->rootBag = null;
        $this->bags = [];
        $this->flashBags = [];
    }

    private function dropCachedNamespace(string $name): void
    {
        $this->rootBag = null;
        unset($this->bags[$name], $this->flashBags[$name]);
    }
}
