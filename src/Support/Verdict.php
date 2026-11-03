<?php

namespace Rowbird\SafeUrl\Support;

use Rowbird\SafeUrl\Enums\Category;

/**
 * One detector saying "this URL belongs to this category".
 */
final class Verdict
{
    public function __construct(
        public readonly Category $category,
        public readonly string $detector,
        public readonly string $reason,
        public readonly ?string $matched = null,
    ) {}

    /**
     * @return array{category: string, detector: string, reason: string, matched: ?string}
     */
    public function toArray(): array
    {
        return [
            'category' => $this->category->value,
            'detector' => $this->detector,
            'reason' => $this->reason,
            'matched' => $this->matched,
        ];
    }
}
