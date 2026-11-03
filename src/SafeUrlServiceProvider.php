<?php

namespace Rowbird\SafeUrl;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\ServiceProvider;
use Illuminate\Validation\Rule;
use Rowbird\SafeUrl\Blocklist\BlocklistStore;
use Rowbird\SafeUrl\Blocklist\BlocklistSyncer;
use Rowbird\SafeUrl\Console\CheckCommand;
use Rowbird\SafeUrl\Console\SyncCommand;
use Rowbird\SafeUrl\Contracts\HostResolver;
use Rowbird\SafeUrl\Http\NativeHostResolver;
use Rowbird\SafeUrl\Http\SafeFetcher;
use Rowbird\SafeUrl\Rules\SafeUrlRule;
use Rowbird\SafeUrl\Rules\StringRules;

class SafeUrlServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/safe-url.php', 'safe-url');

        $this->app->singleton(HostResolver::class, NativeHostResolver::class);

        $this->app->bind(SafeFetcher::class, fn (Application $app) => new SafeFetcher(
            $app->make(HttpFactory::class),
            $app->make(HostResolver::class),
            $app['config']->get('safe-url.http', []),
        ));

        $this->app->singleton(BlocklistStore::class, fn (Application $app) => new BlocklistStore(
            $app['config']->get('safe-url.detectors.blocklist.path') ?? $app->storagePath('safe-url/blocklist.sqlite'),
        ));

        $this->app->bind(BlocklistSyncer::class, fn (Application $app) => new BlocklistSyncer(
            $app->make(HttpFactory::class),
            $app->make(BlocklistStore::class),
            $app['config']->get('safe-url.sources', []),
        ));

        $this->app->singleton(SafeUrlManager::class, fn (Application $app) => new SafeUrlManager(
            $app,
            $app['config']->get('safe-url', []),
        ));
    }

    public function boot(): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'safe-url');

        $this->callAfterResolving(ValidationFactory::class, function (ValidationFactory $factory) {
            StringRules::register($factory);
        });

        if (method_exists(Rule::class, 'macro')) {
            Rule::macro('safeUrl', fn () => new SafeUrlRule);
        }

        if ($this->app->runningInConsole()) {
            $this->commands([SyncCommand::class, CheckCommand::class]);

            $this->publishes([
                __DIR__.'/../config/safe-url.php' => config_path('safe-url.php'),
            ], 'safe-url-config');

            $this->publishes([
                __DIR__.'/../lang' => $this->app->langPath('vendor/safe-url'),
            ], 'safe-url-lang');
        }
    }
}
