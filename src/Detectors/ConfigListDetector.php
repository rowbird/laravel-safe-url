<?php

namespace Rowbird\SafeUrl\Detectors;

use Rowbird\SafeUrl\Contracts\Detector;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Support\Inspection;
use Rowbird\SafeUrl\Support\Verdict;

/**
 * Domains mapped to a category in code or config. Also backs SafeUrl::fake().
 */
final class ConfigListDetector implements Detector
{
    /**
     * @param  array<string, Category|string|list<Category|string>>  $domains
     */
    public function __construct(
        private readonly array $domains,
        private readonly string $name = 'deny',
    ) {}

    public function categories(): array
    {
        return Category::cases();
    }

    public function inspect(Inspection $inspection): array
    {
        $verdicts = [];

        foreach ($inspection->targets() as $target) {
            foreach ($this->domains as $domain => $categories) {
                if (! $target->matches($domain)) {
                    continue;
                }

                foreach (Category::list($categories) as $category) {
                    if ($inspection->wants($category)) {
                        $verdicts[] = new Verdict($category, $this->name, "Matched [{$domain}]", $target->host);
                    }
                }
            }
        }

        return $verdicts;
    }
}
