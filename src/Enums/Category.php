<?php

namespace Rowbird\SafeUrl\Enums;

use InvalidArgumentException;

enum Category: string
{
    case Adult = 'adult';
    case Malware = 'malware';
    case Phishing = 'phishing';
    case Gambling = 'gambling';

    public static function resolve(self|string $value): self
    {
        if ($value instanceof self) {
            return $value;
        }

        return self::tryFrom(strtolower(trim($value)))
            ?? throw new InvalidArgumentException("Unknown safe-url category [{$value}].");
    }

    /**
     * @param  iterable<self|string>|self|string  $values
     * @return list<self>
     */
    public static function list(iterable|self|string $values): array
    {
        $values = is_iterable($values) ? $values : [$values];
        $out = [];

        foreach ($values as $value) {
            $category = self::resolve($value);
            $out[$category->value] = $category;
        }

        return array_values($out);
    }
}
