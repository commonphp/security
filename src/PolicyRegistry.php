<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use ArrayIterator;
use CommonPHP\Security\Contracts\PolicyInterface;
use CommonPHP\Security\Exceptions\AuthorizationException;
use CommonPHP\Security\Exceptions\PolicyNotFoundException;
use Countable;
use IteratorAggregate;
use Traversable;

/**
 * @implements IteratorAggregate<string, PolicyInterface>
 */
final class PolicyRegistry implements Countable, IteratorAggregate
{
    /**
     * @var array<string, PolicyInterface>
     */
    private array $policies = [];

    /**
     * @param iterable<PolicyInterface> $policies
     */
    public function __construct(iterable $policies = [])
    {
        foreach ($policies as $name => $policy) {
            $this->add($policy, is_string($name) ? $name : null);
        }
    }

    public function add(PolicyInterface $policy, ?string $name = null): static
    {
        $name ??= $policy->name();
        $this->policies[$this->normalizeName($name)] = $policy;

        return $this;
    }

    public function has(string $name): bool
    {
        return isset($this->policies[$this->normalizeName($name)]);
    }

    public function get(string $name): PolicyInterface
    {
        $name = $this->normalizeName($name);

        return $this->policies[$name] ?? throw PolicyNotFoundException::forName($name);
    }

    public function remove(string $name): static
    {
        unset($this->policies[$this->normalizeName($name)]);

        return $this;
    }

    public function clear(): static
    {
        $this->policies = [];

        return $this;
    }

    /**
     * @return array<string, PolicyInterface>
     */
    public function all(): array
    {
        return $this->policies;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->policies);
    }

    /**
     * @return list<PolicyInterface>
     */
    public function matching(Permission|string $permission, mixed $resource = null): array
    {
        $matches = [];

        foreach ($this->policies as $policy) {
            if ($policy->supports($permission, $resource)) {
                $matches[] = $policy;
            }
        }

        return $matches;
    }

    public function count(): int
    {
        return count($this->policies);
    }

    /**
     * @return Traversable<string, PolicyInterface>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->policies);
    }

    private function normalizeName(string $name): string
    {
        $name = trim($name);

        if ($name === '') {
            throw AuthorizationException::invalidPolicyName($name);
        }

        return $name;
    }
}
