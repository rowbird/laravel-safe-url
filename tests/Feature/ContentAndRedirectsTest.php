<?php

use Illuminate\Support\Facades\Http;
use Rowbird\SafeUrl\Contracts\HostResolver;
use Rowbird\SafeUrl\Facades\SafeUrl;
use Rowbird\SafeUrl\Http\SafeFetcher;
use Rowbird\SafeUrl\Support\Target;
use Rowbird\SafeUrl\Tests\Support\FakeResolver;

beforeEach(function () {
    seedBlocklist(['naughty.test' => 'adult']);
});

it('detects the RTA label in a meta tag', function () {
    $this->configure(['detectors.content.enabled' => true]);

    Http::fake(['rta.test/*' => Http::response(
        '<html><head><meta name="RATING" content="RTA-5042-1996-1400-1577-RTA" /></head><body></body></html>',
        200, ['Content-Type' => 'text/html; charset=utf-8'],
    )]);

    $result = SafeUrl::check('https://rta.test/');

    expect($result->isAdult())->toBeTrue()
        ->and($result->verdict()->detector)->toBe('content');
});

it('detects the RTA label in the Rating header and adult meta ratings', function () {
    $this->configure(['detectors.content.enabled' => true]);

    Http::fake([
        'header.test/*' => Http::response('{}', 200, ['Content-Type' => 'application/json', 'Rating' => 'RTA-5042-1996-1400-1577-RTA']),
        'mature.test/*' => Http::response("<head><meta content='mature' name='rating'></head>"),
        'clean.test/*' => Http::response('<head><meta name="rating" content="general"><title>Recipes</title></head>'),
    ]);

    expect(SafeUrl::check('https://header.test/')->isAdult())->toBeTrue()
        ->and(SafeUrl::check('https://mature.test/')->isAdult())->toBeTrue()
        ->and(SafeUrl::check('https://clean.test/')->isSafe())->toBeTrue();
});

it('uses the keyword heuristic only when configured', function () {
    $html = '<head><title>Hot videos XXX</title><meta name="description" content="Free cams and nsfw clips"></head>';

    Http::fake(['*' => fn () => Http::response($html)]);

    $this->configure(['detectors.content.enabled' => true]);
    expect(SafeUrl::check('https://kw.test/')->isSafe())->toBeTrue();

    $this->configure([
        'detectors.content.keywords' => ['xxx', 'nsfw', 'cams'],
        'detectors.content.keyword_threshold' => 2,
    ]);

    $result = SafeUrl::check('https://kw2.test/');
    expect($result->isAdult())->toBeTrue()
        ->and($result->verdict()->reason)->toContain('xxx');
});

it('refuses to fetch hosts that resolve to private addresses', function () {
    $this->configure(['detectors.content.enabled' => true]);
    $this->app->instance(HostResolver::class, new FakeResolver(['internal.test' => ['10.0.0.5']]));

    Http::fake();

    $result = SafeUrl::check('http://internal.test/admin');

    expect($result->isSafe())->toBeTrue()
        ->and($result->errors['content'])->toContain('non-public address');

    SafeUrl::check('http://169.254.169.254/latest/meta-data');

    Http::assertNothingSent();
});

it('follows shortener redirects and checks every host in the chain', function () {
    $this->configure(['http.follow_redirects' => true]);

    Http::fake([
        'short.test/*' => Http::response('', 301, ['Location' => 'https://hop.test/go']),
        // relative redirect stays on hop.test, then jumps to the listed domain
        'hop.test/final' => Http::response('', 302, ['Location' => 'https://www.naughty.test/']),
        'hop.test/*' => Http::response('', 302, ['Location' => '/final']),
        'www.naughty.test/*' => Http::response('<html></html>'),
    ]);

    $result = SafeUrl::check('https://short.test/abc');

    expect($result->isAdult())->toBeTrue()
        ->and($result->verdict()->matched)->toBe('naughty.test');
});

it('stops a redirect into the internal network', function () {
    $this->configure(['detectors.content.enabled' => true]);

    Http::fake(['*' => Http::response('', 302, ['Location' => 'http://127.0.0.1:6379/'])]);

    $result = SafeUrl::check('https://redirector.test/');

    expect($result->errors['content'])->toContain('non-public address');
    Http::assertSentCount(1);
});

it('gives up after too many redirects and caps the body size', function () {
    $fetcher = new SafeFetcher(app('Illuminate\Http\Client\Factory'), new FakeResolver, ['max_redirects' => 1, 'max_bytes' => 10]);

    Http::fake([
        'loop.test/*' => Http::response('', 302, ['Location' => 'https://loop.test/again']),
        'big.test/*' => Http::response(str_repeat('a', 100)),
    ]);

    expect(fn () => $fetcher->fetch('https://loop.test/'))->toThrow(\Rowbird\SafeUrl\Exceptions\FetchException::class, 'Too many redirects');

    $page = $fetcher->fetch('https://big.test/');
    expect(strlen($page->body))->toBe(10)->and($page->truncated)->toBeTrue();
});

it('resolves relative redirect locations', function (string $location, string $expected) {
    expect(SafeFetcher::resolveLocation(Target::parse('https://a.test:8443/dir/page?x=1'), $location))->toBe($expected);
})->with([
    ['https://b.test/x', 'https://b.test/x'],
    ['//c.test/y', 'https://c.test/y'],
    ['/root', 'https://a.test:8443/root'],
    ['sibling', 'https://a.test:8443/dir/sibling'],
]);
