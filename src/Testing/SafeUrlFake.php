<?php

namespace Rowbird\SafeUrl\Testing;

use Illuminate\Contracts\Container\Container;
use PHPUnit\Framework\Assert as PHPUnit;
use Rowbird\SafeUrl\Detectors\ConfigListDetector;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\SafeUrlManager;
use Rowbird\SafeUrl\Support\Result;

class SafeUrlFake extends SafeUrlManager
{
    /** @var list<string> */
    protected array $checked = [];

    /**
     * @param  array<string, Category|string|list<Category|string>>  $domains
     */
    public function __construct(Container $container, protected array $domains = [])
    {
        $config = $container->make('config')->get('safe-url', []);
        $config['cache']['enabled'] = false;
        $config['allow'] = [];
        $config['deny'] = [];
        $config['detectors'] = [];
        $config['http']['follow_redirects'] = false;

        parent::__construct($container, $config);

        $this->extend('fake', new ConfigListDetector($domains, 'fake'));
    }

    public function check(string $url, iterable|Category|string|null $categories = null): Result
    {
        $this->checked[] = $url;

        return parent::check($url, $categories);
    }

    /**
     * @param  Category|string|list<Category|string>  $categories
     */
    public function flag(string $domain, Category|string|array $categories): static
    {
        $this->domains[$domain] = $categories;

        return $this->extend('fake', new ConfigListDetector($this->domains, 'fake'));
    }

    public function assertChecked(string $url): void
    {
        PHPUnit::assertContains($url, $this->checked, "The URL [{$url}] was not checked.");
    }

    public function assertNotChecked(string $url): void
    {
        PHPUnit::assertNotContains($url, $this->checked, "The URL [{$url}] was checked.");
    }

    public function assertNothingChecked(): void
    {
        PHPUnit::assertEmpty($this->checked, 'URLs were checked: '.implode(', ', $this->checked));
    }

    /**
     * @return list<string>
     */
    public function checked(): array
    {
        return $this->checked;
    }
}
