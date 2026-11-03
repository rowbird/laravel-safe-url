<?php

namespace Rowbird\SafeUrl\Detectors;

use Rowbird\SafeUrl\Contracts\Detector;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Support\Inspection;
use Rowbird\SafeUrl\Support\Verdict;

/**
 * Flags hosts under top-level domains (or any suffix) that exist for a
 * category, such as .xxx, .porn, .adult and .sex. No lookup needed.
 */
final class TldDetector implements Detector
{
    /** @var array<string, list<Category>> suffix => categories */
    private array $suffixes = [];

    /**
     * @param  array{suffixes?: array<string, Category|string|list<Category|string>>}  $config
     */
    public function __construct(array $config = [])
    {
        foreach ($config['suffixes'] ?? [] as $suffix => $categories) {
            $suffix = strtolower(trim((string) $suffix, ". \t\n\r"));

            if ($suffix !== '') {
                $this->suffixes[$suffix] = Category::list($categories);
            }
        }
    }

    public function categories(): array
    {
        return Category::list(array_merge([], ...array_values($this->suffixes)));
    }

    public function inspect(Inspection $inspection): array
    {
        foreach ($inspection->targets() as $target) {
            if ($target->isIp()) {
                continue;
            }

            foreach ($this->suffixes as $suffix => $categories) {
                if (! str_ends_with($target->host, '.'.$suffix)) {
                    continue;
                }

                foreach ($categories as $category) {
                    if ($inspection->wants($category)) {
                        return [new Verdict($category, 'tld', "Under the .{$suffix} domain", $target->host)];
                    }
                }
            }
        }

        return [];
    }
}
