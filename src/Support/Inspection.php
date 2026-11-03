<?php

namespace Rowbird\SafeUrl\Support;

use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Exceptions\FetchException;
use Rowbird\SafeUrl\Http\FetchedPage;
use Rowbird\SafeUrl\Http\SafeFetcher;

/**
 * What the detectors receive: the URL being checked, the categories asked
 * for, and lazy access to the page (fetched at most once per check).
 */
final class Inspection
{
    private bool $fetched = false;

    private ?FetchedPage $page = null;

    private ?string $fetchError = null;

    /**
     * @param  list<Category>  $categories
     */
    public function __construct(
        public readonly Target $target,
        public readonly array $categories,
        private readonly ?SafeFetcher $fetcher = null,
        private readonly bool $followRedirects = false,
    ) {}

    public function wants(Category $category): bool
    {
        return in_array($category, $this->categories, true);
    }

    /**
     * @param  list<Category>  $categories
     */
    public function wantsAny(array $categories): bool
    {
        foreach ($categories as $category) {
            if ($this->wants($category)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The original target, plus every host in the redirect chain when
     * redirect following is on.
     *
     * @return list<Target>
     */
    public function targets(): array
    {
        $targets = [$this->target->host => $this->target];

        if ($this->followRedirects && ($page = $this->page())) {
            foreach ($page->hops as $hop) {
                $targets[$hop->host] ??= $hop;
            }
        }

        return array_values($targets);
    }

    /**
     * Fetches the page once. Returns null (and records the error) when the
     * fetch fails or was refused.
     */
    public function page(): ?FetchedPage
    {
        if (! $this->fetched) {
            $this->fetched = true;

            if ($this->fetcher === null) {
                $this->fetchError = 'No fetcher configured.';
            } else {
                try {
                    $this->page = $this->fetcher->fetch($this->target->url);
                } catch (FetchException $e) {
                    $this->fetchError = $e->getMessage();
                }
            }
        }

        return $this->page;
    }

    public function fetchError(): ?string
    {
        return $this->fetchError;
    }
}
