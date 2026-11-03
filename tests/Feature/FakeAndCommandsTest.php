<?php

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Rowbird\SafeUrl\Events\UnsafeUrlDetected;
use Rowbird\SafeUrl\Facades\SafeUrl;

it('fakes detections without touching the network or the blocklist', function () {
    Http::fake();

    $fake = SafeUrl::fake(['naughty.test' => 'adult', 'evil.test' => ['malware', 'phishing']]);

    expect(Validator::make(['site' => 'https://naughty.test'], ['site' => 'not_adult'])->fails())->toBeTrue()
        ->and(SafeUrl::check('evil.test', ['malware', 'phishing'])->categories())->toHaveCount(2)
        ->and(SafeUrl::isSafe('fine.test'))->toBeTrue()
        ->and(SafeUrl::check('fine.test')->hasErrors())->toBeFalse();

    $fake->flag('later.test', 'gambling');
    expect(SafeUrl::check('later.test', 'gambling')->isGambling())->toBeTrue();

    $fake->assertChecked('https://naughty.test');
    $fake->assertNotChecked('https://never.test');
    Http::assertNothingSent();
});

it('dispatches an event for unsafe urls', function () {
    Event::fake([UnsafeUrlDetected::class]);
    SafeUrl::fake(['naughty.test' => 'adult']);

    SafeUrl::check('naughty.test');
    SafeUrl::check('fine.test');

    Event::assertDispatchedTimes(UnsafeUrlDetected::class, 1);
    Event::assertDispatched(fn (UnsafeUrlDetected $e) => $e->result->host === 'naughty.test');
});

it('checks a url from the command line', function () {
    seedBlocklist(['naughty.test' => 'adult']);

    $this->artisan('safe-url:check', ['url' => 'https://naughty.test'])
        ->expectsOutputToContain('adult via blocklist')
        ->expectsOutputToContain('Unsafe')
        ->assertExitCode(1);

    $this->artisan('safe-url:check', ['url' => 'example.com', '--category' => ['adult']])
        ->expectsOutputToContain('Safe.')
        ->assertSuccessful();

    $this->artisan('safe-url:check', ['url' => 'not a url'])->assertExitCode(2);
});

it('prints json from the command line', function () {
    seedBlocklist(['naughty.test' => 'adult']);

    $this->artisan('safe-url:check', ['url' => 'naughty.test', '--json' => true])
        ->expectsOutputToContain('"categories": [')
        ->assertExitCode(1);
});
