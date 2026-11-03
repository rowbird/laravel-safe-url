<?php

namespace Rowbird\SafeUrl\Contracts;

interface HostResolver
{
    /**
     * IP addresses (v4 and v6) the host resolves to.
     *
     * @return list<string>
     */
    public function resolve(string $host): array;
}
