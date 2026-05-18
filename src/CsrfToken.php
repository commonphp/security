<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use CommonPHP\Security\Exceptions\InvalidCsrfTokenException;
use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use Stringable;
use Throwable;

final readonly class CsrfToken implements Stringable
{
    public const int MAX_ID_LENGTH = 128;

    private string $id;

    private string $value;

    private DateTimeImmutable $createdAt;

    public function __construct(string $id, string $value, ?DateTimeImmutable $createdAt = null)
    {
        $this->id = self::normalizeId($id);
        $this->value = self::normalizeValue($value);
        $this->createdAt = $createdAt ?? new DateTimeImmutable();
    }

    public static function create(string $id, string $value, ?DateTimeImmutable $createdAt = null): self
    {
        return new self($id, $value, $createdAt);
    }

    /**
     * @param array{id?: mixed, value?: mixed, createdAt?: mixed} $payload
     */
    public static function fromArray(array $payload): self
    {
        if (!isset($payload['id'], $payload['value']) || !is_string($payload['id']) || !is_string($payload['value'])) {
            throw InvalidCsrfTokenException::malformed('<unknown>');
        }

        $createdAt = null;

        if (isset($payload['createdAt'])) {
            if (!is_string($payload['createdAt'])) {
                throw InvalidCsrfTokenException::malformed($payload['id']);
            }

            try {
                $createdAt = new DateTimeImmutable($payload['createdAt']);
            } catch (Throwable) {
                throw InvalidCsrfTokenException::malformed($payload['id']);
            }
        }

        return new self($payload['id'], $payload['value'], $createdAt);
    }

    public static function normalizeId(string $id): string
    {
        $id = trim($id);

        if ($id === '' || strlen($id) > self::MAX_ID_LENGTH || preg_match('/^[A-Za-z0-9_.:-]+$/', $id) !== 1) {
            throw InvalidCsrfTokenException::invalidId($id);
        }

        return $id;
    }

    public function id(): string
    {
        return $this->id;
    }

    public function value(): string
    {
        return $this->value;
    }

    public function createdAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function matches(string|self $value): bool
    {
        $value = $value instanceof self ? $value->value() : $value;

        return hash_equals($this->value, $value);
    }

    public function isExpired(DateInterval $ttl, ?DateTimeInterface $now = null): bool
    {
        $now = $now === null ? new DateTimeImmutable() : DateTimeImmutable::createFromInterface($now);

        return $this->createdAt->add($ttl) <= $now;
    }

    /**
     * @return array{id: string, value: string, createdAt: string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'value' => $this->value,
            'createdAt' => $this->createdAt->format(DATE_ATOM),
        ];
    }

    public function __toString(): string
    {
        return $this->value;
    }

    private static function normalizeValue(string $value): string
    {
        if ($value === '' || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw InvalidCsrfTokenException::invalidValue();
        }

        return $value;
    }
}
