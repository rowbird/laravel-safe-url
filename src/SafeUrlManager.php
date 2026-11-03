<?php

namespace Rowbird\SafeUrl;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use InvalidArgumentException;
use Rowbird\SafeUrl\Contracts\Detector;
use Rowbird\SafeUrl\Detectors\BlocklistDetector;
use Rowbird\SafeUrl\Detectors\CloudflareDnsDetector;
use Rowbird\SafeUrl\Detectors\ConfigListDetector;
use Rowbird\SafeUrl\Detectors\ContentDetector;
use Rowbird\SafeUrl\Detectors\SafeBrowsingDetector;
use Rowbird\SafeUrl\Detectors\TldDetector;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Events\UnsafeUrlDetected;
use Rowbird\SafeUrl\Exceptions\DetectorException;
use Rowbird\SafeUrl\Exceptions\InvalidUrlException;
use Rowbird\SafeUrl\Http\SafeFetcher;
use Rowbird\SafeUrl\Rules\SafeUrlRule;
use Rowbird\SafeUrl\Support\Inspection;
use Rowbird\SafeUrl\Support\Result;
use Rowbird\SafeUrl\Support\Target;
use Rowbird\SafeUrl\Support\Verdict;

class SafeUrlManager
{
    public const BUILTIN_DETECTORS = [
        'tld' => TldDetector::class,
        'blocklist' => BlocklistDetector::class,
        'cloudflare' => CloudflareDnsDetector::class,
        'safe_browsing' => SafeBrowsingDetector::class,
        'content' => ContentDetector::class,
    ];

    /** @var array<string, Detector>|null */
    protected ?array $detectors = null;

    /** @var array<string, Detector> */
    protected array $extended = [];

    public function __construct(
        protected readonly Container $container,
        protected array $config,
    ) {}

    /**
     * @param  iterable<Category|string>|Category|string|null  $categories  null = config('safe-url.categories')
     *
     * @throws InvalidUrlException
     */
    public function check(string $url, iterable|Category|string|null $categories = null): Result
    {
        $target = Target::parse($url) ?? throw InvalidUrlException::for($url);
        $categories = Category::list($categories ?? $this->config['categories'] ?? ['adult', 'malware', 'phishing']);

        foreach ($this->config['allow'] ?? [] as $domain) {
            if ($target->matches($domain)) {
                return new Result($target->url, $target->host, checked: $categories, allowlisted: true);
            }
        }

        if (! ($this->config['cache']['enabled'] ?? false)) {
            return $this->run($target, $categories);
        }

        $cache = $this->cache();
        $key = $this->cacheKey($target, $categories);

        // Stored as a plain array: works with cache stores that refuse to
        // unserialize objects (cache.serializable_classes).
        if (is_array($cached = $cache->get($key))) {
            return Result::fromArray($cached);
        }

        $result = $this->run($target, $categories);

        if (! $result->hasErrors()) {
            $cache->put($key, $result->toArray(), (int) ($this->config['cache']['ttl'] ?? 86400));
        }

        return $result;
    }

    public function isSafe(string $url, iterable|Category|string|null $categories = null): bool
    {
        return $this->check($url, $categories)->isSafe();
    }

    public function isUnsafe(string $url, iterable|Category|string|null $categories = null): bool
    {
        return $this->check($url, $categories)->isUnsafe();
    }

    public function isAdult(string $url): bool
    {
        return $this->check($url, Category::Adult)->isUnsafe();
    }

    public function rule(): SafeUrlRule
    {
        return new SafeUrlRule;
    }

    /**
     * Register a detector at runtime: SafeUrl::extend('my-api', new MyDetector).
     */
    public function extend(string $name, Detector $detector): static
    {
        $this->extended[$name] = $detector;
        $this->detectors = null;

        return $this;
    }

    /**
     * Invalidate every cached result (done automatically after safe-url:sync).
     */
    public function flushCache(): void
    {
        $this->cache()->forever($this->generationKey(), bin2hex(random_bytes(6)));
    }

    public function config(?string $key = null, mixed $default = null): mixed
    {
        return $key === null ? $this->config : data_get($this->config, $key, $default);
    }

    /**
     * @return array<string, Detector>
     */
    public function detectors(): array
    {
        return $this->detectors ??= [...$this->buildDetectors(), ...$this->extended];
    }

    /**
     * @param  list<Category>  $categories
     */
    protected function run(Target $target, array $categories): Result
    {
        $inspection = new Inspection(
            $target,
            $categories,
            $this->container->make(SafeFetcher::class),
            (bool) ($this->config['http']['follow_redirects'] ?? false),
        );

        $verdicts = [];
        $errors = [];

        foreach ($this->detectors() as $name => $detector) {
            if (! $inspection->wantsAny($detector->categories())) {
                continue;
            }

            try {
                $found = array_values(array_filter(
                    $detector->inspect($inspection),
                    fn (Verdict $v) => $inspection->wants($v->category),
                ));
            } catch (DetectorException $e) {
                $errors[$name] = $e->getMessage();

                continue;
            }

            array_push($verdicts, ...$found);

            if ($verdicts !== [] && ($this->config['stop_on_first'] ?? true)) {
                break;
            }
        }

        if (($this->config['http']['follow_redirects'] ?? false) && $inspection->fetchError() !== null && ! isset($errors['content'])) {
            $errors['redirects'] = $inspection->fetchError();
        }

        $result = new Result($target->url, $target->host, $verdicts, $errors, $categories);

        if ($result->isUnsafe() && $this->container->bound(Dispatcher::class)) {
            $this->container->make(Dispatcher::class)->dispatch(new UnsafeUrlDetected($result));
        }

        return $result;
    }

    /**
     * @return array<string, Detector>
     */
    protected function buildDetectors(): array
    {
        $detectors = [];

        if (! empty($this->config['deny'])) {
            $detectors['deny'] = new ConfigListDetector($this->config['deny'], 'deny');
        }

        foreach ($this->config['detectors'] ?? [] as $name => $options) {
            if (! ($options['enabled'] ?? true)) {
                continue;
            }

            $class = $options['class'] ?? self::BUILTIN_DETECTORS[$name]
                ?? throw new InvalidArgumentException("Detector [{$name}] has no class.");

            $detector = $this->container->make($class, ['config' => $options]);

            if (! $detector instanceof Detector) {
                throw new InvalidArgumentException("[{$class}] must implement ".Detector::class.'.');
            }

            $detectors[$name] = $detector;
        }

        return $detectors;
    }

    /**
     * @param  list<Category>  $categories
     */
    protected function cacheKey(Target $target, array $categories): string
    {
        $values = array_map(fn (Category $c) => $c->value, $categories);
        sort($values);

        $generation = $this->cache()->get($this->generationKey(), '0');

        return $this->prefix().':'.$generation.':'.sha1(strtolower($target->url).'|'.implode(',', $values));
    }

    protected function generationKey(): string
    {
        return $this->prefix().':generation';
    }

    protected function prefix(): string
    {
        return $this->config['cache']['prefix'] ?? 'safe-url';
    }

    protected function cache(): \Illuminate\Contracts\Cache\Repository
    {
        return $this->container->make(CacheFactory::class)->store($this->config['cache']['store'] ?? null);
    }
}
