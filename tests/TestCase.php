<?php

namespace Rowbird\SafeUrl\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Rowbird\SafeUrl\Contracts\HostResolver;
use Rowbird\SafeUrl\SafeUrlServiceProvider;
use Rowbird\SafeUrl\Tests\Support\FakeResolver;

abstract class TestCase extends Orchestra
{
    protected string $blocklistPath;

    protected function getPackageProviders($app): array
    {
        return [SafeUrlServiceProvider::class];
    }

    protected function getPackageAliases($app): array
    {
        return ['SafeUrl' => \Rowbird\SafeUrl\Facades\SafeUrl::class];
    }

    protected function defineEnvironment($app): void
    {
        $this->blocklistPath = sys_get_temp_dir().'/safe-url-tests/'.uniqid('', true).'/blocklist.sqlite';

        $app['config']->set('cache.default', 'array');
        $app['config']->set('safe-url.detectors.blocklist.path', $this->blocklistPath);
        // Network detectors are switched on per test, with Http::fake().
        $app['config']->set('safe-url.detectors.cloudflare.enabled', false);
        $app['config']->set('safe-url.detectors.safe_browsing.enabled', false);
        $app['config']->set('safe-url.detectors.content.enabled', false);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->app->instance(HostResolver::class, new FakeResolver);
    }

    protected function tearDown(): void
    {
        if (isset($this->blocklistPath) && is_dir(dirname($this->blocklistPath))) {
            array_map('unlink', glob(dirname($this->blocklistPath).'/*') ?: []);
            @rmdir(dirname($this->blocklistPath));
        }

        parent::tearDown();
    }

    /**
     * Point the package at a fresh config (the manager is a singleton built from it).
     */
    protected function configure(array $values): void
    {
        foreach ($values as $key => $value) {
            config()->set("safe-url.{$key}", $value);
        }

        $this->app->forgetInstance(\Rowbird\SafeUrl\SafeUrlManager::class);
        \Rowbird\SafeUrl\Facades\SafeUrl::clearResolvedInstances();
    }
}
