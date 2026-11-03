<?php

namespace Rowbird\SafeUrl\Detectors;

use Rowbird\SafeUrl\Blocklist\BlocklistStore;
use Rowbird\SafeUrl\Contracts\Detector;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Exceptions\DetectorException;
use Rowbird\SafeUrl\Support\Inspection;
use Rowbird\SafeUrl\Support\Verdict;
use Throwable;

final class BlocklistDetector implements Detector
{
    public function __construct(private readonly BlocklistStore $store) {}

    public function categories(): array
    {
        return Category::cases();
    }

    public function inspect(Inspection $inspection): array
    {
        if (! $this->store->exists()) {
            throw new DetectorException('Blocklist not found. Run `php artisan safe-url:sync`.');
        }

        $categories = array_map(fn (Category $c) => $c->value, $inspection->categories);

        foreach ($inspection->targets() as $target) {
            try {
                $match = $this->store->lookup($target->candidates(), $categories);
            } catch (Throwable $e) {
                throw new DetectorException('Blocklist lookup failed: '.$e->getMessage(), previous: $e);
            }

            if ($match !== null) {
                return [new Verdict(
                    Category::from($match['category']),
                    'blocklist',
                    "Listed in {$match['source']}",
                    $match['domain'],
                )];
            }
        }

        return [];
    }
}
