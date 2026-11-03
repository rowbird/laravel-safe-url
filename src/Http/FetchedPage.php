<?php

namespace Rowbird\SafeUrl\Http;

use Rowbird\SafeUrl\Support\Target;

final class FetchedPage
{
    /**
     * @param  array<string, list<string>>  $headers  lower-cased names
     * @param  list<Target>  $hops  every URL visited, first to last
     */
    public function __construct(
        public readonly string $url,
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
        public readonly array $hops,
        public readonly bool $truncated = false,
    ) {}

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)][0] ?? null;
    }

    public function isHtml(): bool
    {
        $type = $this->header('content-type');

        return $type === null || str_contains(strtolower($type), 'html');
    }
}
