<?php

namespace Rowbird\SafeUrl\Blocklist;

use Illuminate\Http\Client\Factory as HttpFactory;
use Rowbird\SafeUrl\Enums\Category;
use RuntimeException;
use Throwable;

/**
 * Downloads (or reads) every configured source and rebuilds the store. A source
 * that fails keeps the domains it already had, so a bad download never opens a
 * hole in the blocklist until the next sync.
 */
final class BlocklistSyncer
{
    /**
     * @param  list<array{category: string, url?: string, path?: string}>  $sources
     */
    public function __construct(
        private readonly HttpFactory $http,
        private readonly BlocklistStore $store,
        private readonly array $sources,
    ) {}

    /**
     * @param  (callable(string $source, ?int $domains, ?string $error): void)|null  $progress
     * @return array{inserted: int, sources: list<array{source: string, category: string, domains: ?int, error: ?string}>}
     */
    public function sync(?callable $progress = null): array
    {
        $report = [];
        $loaded = [];
        $failed = [];

        foreach ($this->sources as $source) {
            $category = Category::resolve($source['category'] ?? '')->value;

            $name = $source['url'] ?? $source['path'] ?? '(unnamed)';

            try {
                $contents = $this->read($source);
                $count = 0;

                foreach (ListParser::domains($contents) as $_) {
                    $count++;
                }

                if ($count === 0) {
                    throw new RuntimeException('No domains found in the source.');
                }

                // Keep only one source in memory at a time.
                $tmp = tempnam(sys_get_temp_dir(), 'safe-url-');
                file_put_contents($tmp, $contents);
                unset($contents);

                $loaded[] = [$name, $category, $tmp];
                $report[] = ['source' => $name, 'category' => $category, 'domains' => $count, 'error' => null];
                $progress && $progress($name, $count, null);
            } catch (Throwable $e) {
                $failed[] = $name;
                $report[] = ['source' => $name, 'category' => $category, 'domains' => null, 'error' => $e->getMessage()];
                $progress && $progress($name, null, $e->getMessage());
            }
        }

        if ($loaded === []) {
            throw new RuntimeException('No blocklist source could be loaded; the current blocklist was kept.');
        }

        try {
            $inserted = $this->store->rebuild((function () use ($loaded, $failed) {
                foreach ($loaded as [$name, $category, $file]) {
                    foreach (ListParser::domains((string) file_get_contents($file)) as $domain) {
                        yield [$domain, $category, $name];
                    }
                }

                foreach ($failed as $name) {
                    yield from $this->store->rowsFromSource($name);
                }
            })());
        } finally {
            foreach ($loaded as [, , $file]) {
                @unlink($file);
            }
        }

        return ['inserted' => $inserted, 'sources' => $report];
    }

    /**
     * @param  array{url?: string, path?: string}  $source
     */
    private function read(array $source): string
    {
        if (! empty($source['path'])) {
            $contents = @file_get_contents($source['path']);

            if ($contents === false) {
                throw new RuntimeException("Could not read [{$source['path']}].");
            }

            return $contents;
        }

        if (empty($source['url'])) {
            throw new RuntimeException('Source has neither a url nor a path.');
        }

        $response = $this->http
            ->timeout(120)
            ->connectTimeout(10)
            ->retry(2, 1000, throw: false)
            ->withUserAgent('laravel-safe-url (+https://github.com/rowbird/laravel-safe-url)')
            ->get($source['url']);

        if (! $response->successful()) {
            throw new RuntimeException("HTTP {$response->status()}");
        }

        return $response->body();
    }
}
