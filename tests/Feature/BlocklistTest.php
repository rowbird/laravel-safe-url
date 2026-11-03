<?php

use Illuminate\Support\Facades\Http;
use Rowbird\SafeUrl\Blocklist\BlocklistStore;
use Rowbird\SafeUrl\Facades\SafeUrl;

it('flags a listed domain and its subdomains', function () {
    seedBlocklist(['naughty.test' => 'adult', 'evil.test' => 'malware']);

    $result = SafeUrl::check('https://videos.naughty.test/watch?v=1');

    expect($result->isUnsafe())->toBeTrue()
        ->and($result->isAdult())->toBeTrue()
        ->and($result->verdict()->detector)->toBe('blocklist')
        ->and($result->verdict()->matched)->toBe('naughty.test');

    expect(SafeUrl::check('evil.test')->isMalware())->toBeTrue();
    expect(SafeUrl::isSafe('https://example.com'))->toBeTrue();
});

it('only reports the categories that were asked for', function () {
    seedBlocklist(['casino.test' => 'gambling']);

    expect(SafeUrl::isSafe('casino.test'))->toBeTrue() // gambling is not a default category
        ->and(SafeUrl::check('casino.test', 'gambling')->isGambling())->toBeTrue()
        ->and(SafeUrl::check('casino.test', ['adult', 'gambling'])->categories())->toHaveCount(1);
});

it('does not match look-alike domains', function () {
    seedBlocklist(['naughty.test' => 'adult']);

    expect(SafeUrl::isSafe('notnaughty.test'))->toBeTrue()
        ->and(SafeUrl::isSafe('naughty.test.example.com'))->toBeTrue();
});

it('reports an error, not a pass, when the blocklist was never synced', function () {
    $result = SafeUrl::check('https://example.com');

    expect($result->isSafe())->toBeTrue()
        ->and($result->isInconclusive())->toBeTrue()
        ->and($result->errors)->toHaveKey('blocklist');
});

it('syncs every format from remote and local sources', function () {
    $local = tempnam(sys_get_temp_dir(), 'list');
    file_put_contents($local, "my-own-list.test\n");

    config()->set('safe-url.sources', [
        ['category' => 'adult', 'url' => 'https://lists.test/porn.txt'],
        ['category' => 'malware', 'url' => 'https://lists.test/malware.hosts.gz'],
        ['category' => 'adult', 'path' => $local],
        ['category' => 'phishing', 'url' => 'https://lists.test/down.txt'],
    ]);

    Http::fake([
        'lists.test/porn.txt' => Http::response("# header\nnaughty.test\n||adblock-style.test^\n"),
        'lists.test/malware.hosts.gz' => Http::response(gzencode("0.0.0.0 evil.test\n")),
        'lists.test/down.txt' => Http::response('', 500),
    ]);

    $this->artisan('safe-url:sync')
        ->expectsOutputToContain('failed: HTTP 500')
        ->assertExitCode(1);

    expect(app(BlocklistStore::class)->stats()['counts'])->toBe(['adult' => 3, 'malware' => 1]);
    expect(SafeUrl::check('adblock-style.test')->isAdult())->toBeTrue()
        ->and(SafeUrl::check('www.evil.test')->isMalware())->toBeTrue()
        ->and(SafeUrl::check('my-own-list.test')->isAdult())->toBeTrue();

    unlink($local);
});

it('keeps the current blocklist when every source fails', function () {
    seedBlocklist(['naughty.test' => 'adult']);

    config()->set('safe-url.sources', [['category' => 'adult', 'url' => 'https://lists.test/a.txt']]);
    Http::fake(['*' => Http::response('', 503)]);

    $this->artisan('safe-url:sync')->assertExitCode(1);

    expect(SafeUrl::check('naughty.test')->isAdult())->toBeTrue();
});

it('keeps the domains of a source that failed while others succeeded', function () {
    config()->set('safe-url.sources', [
        ['category' => 'adult', 'url' => 'https://lists.test/porn.txt'],
        ['category' => 'phishing', 'url' => 'https://lists.test/phishing.txt'],
    ]);

    Http::fake([
        'lists.test/porn.txt' => Http::sequence()
            ->push("naughty.test\n")
            ->whenEmpty(Http::response('', 503)),
        'lists.test/phishing.txt' => Http::sequence()
            ->push("old-phish.test\n")
            ->whenEmpty(Http::response("new-phish.test\n")),
    ]);

    $this->artisan('safe-url:sync')->assertSuccessful();
    $this->artisan('safe-url:sync')
        ->expectsOutputToContain('failed: HTTP 503')
        ->assertExitCode(1);

    expect(SafeUrl::check('naughty.test')->isAdult())->toBeTrue()
        ->and(SafeUrl::check('new-phish.test')->isPhishing())->toBeTrue()
        ->and(SafeUrl::isSafe('old-phish.test'))->toBeTrue();
});

it('flags the domain a browser would really open behind a backslash', function () {
    seedBlocklist(['naughty.test' => 'adult']);

    expect(SafeUrl::check('http://naughty.test\\@good.test')->isAdult())->toBeTrue();
});

it('invalidates cached results after a sync', function () {
    seedBlocklist(['old.test' => 'adult']);
    expect(SafeUrl::isSafe('new.test'))->toBeTrue(); // cached as safe

    config()->set('safe-url.sources', [['category' => 'adult', 'url' => 'https://lists.test/a.txt']]);
    Http::fake(['*' => Http::response("new.test\n")]);

    $this->artisan('safe-url:sync')->assertSuccessful();

    expect(SafeUrl::check('new.test')->isAdult())->toBeTrue();
});
