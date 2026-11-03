<?php

namespace Rowbird\SafeUrl\Tests\Support;

use Rowbird\SafeUrl\Contracts\HostResolver;

final class FakeResolver implements HostResolver
{
    /** @param array<string, list<string>> $map */
    public function __construct(public array $map = [], public string $default = '93.184.216.34') {}

    public function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }

        return $this->map[$host] ?? [$this->default];
    }
}
