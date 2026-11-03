<?php

namespace Rowbird\SafeUrl\Facades;

use Illuminate\Support\Facades\Facade;
use Rowbird\SafeUrl\SafeUrlManager;
use Rowbird\SafeUrl\Testing\SafeUrlFake;

/**
 * @method static \Rowbird\SafeUrl\Support\Result check(string $url, iterable|\Rowbird\SafeUrl\Enums\Category|string|null $categories = null)
 * @method static bool isSafe(string $url, iterable|\Rowbird\SafeUrl\Enums\Category|string|null $categories = null)
 * @method static bool isUnsafe(string $url, iterable|\Rowbird\SafeUrl\Enums\Category|string|null $categories = null)
 * @method static bool isAdult(string $url)
 * @method static \Rowbird\SafeUrl\Rules\SafeUrlRule rule()
 * @method static \Rowbird\SafeUrl\SafeUrlManager extend(string $name, \Rowbird\SafeUrl\Contracts\Detector $detector)
 * @method static void flushCache()
 * @method static array detectors()
 *
 * @see SafeUrlManager
 */
class SafeUrl extends Facade
{
    /**
     * Replace every detector with an in-memory list:
     *
     *   SafeUrl::fake(['naughty.test' => 'adult', 'evil.test' => ['malware', 'phishing']]);
     *
     * @param  array<string, \Rowbird\SafeUrl\Enums\Category|string|list<\Rowbird\SafeUrl\Enums\Category|string>>  $domains
     */
    public static function fake(array $domains = []): SafeUrlFake
    {
        $fake = new SafeUrlFake(static::getFacadeApplication(), $domains);

        static::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return SafeUrlManager::class;
    }
}
