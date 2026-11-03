<?php

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Rowbird\SafeUrl\Facades\SafeUrl;

function dnsAnswer(string $host, string $ip): array
{
    return ['Status' => 0, 'Answer' => [['name' => $host, 'type' => 1, 'TTL' => 60, 'data' => $ip]]];
}

beforeEach(function () {
    seedBlocklist(['unrelated.test' => 'adult']);
});

it('classifies a domain blocked only by the family resolver as adult', function () {
    $this->configure(['detectors.cloudflare.enabled' => true]);

    Http::fake([
        'family.cloudflare-dns.com/*' => Http::response(dnsAnswer('adult.test', '0.0.0.0')),
        'security.cloudflare-dns.com/*' => Http::response(dnsAnswer('adult.test', '203.0.113.7')),
    ]);

    $result = SafeUrl::check('https://adult.test');

    expect($result->isAdult())->toBeTrue()
        ->and($result->verdict()->detector)->toBe('cloudflare');

    Http::assertSent(fn (Request $r) => str_contains($r->url(), 'name=adult.test') && $r->hasHeader('Accept', 'application/dns-json'));
});

it('classifies a domain blocked by the security resolver as malware', function () {
    $this->configure(['detectors.cloudflare.enabled' => true]);

    Http::fake(['*' => Http::response(dnsAnswer('bad.test', '0.0.0.0'))]);

    $result = SafeUrl::check('bad.test');

    expect($result->isMalware())->toBeTrue()
        ->and($result->isAdult())->toBeFalse();
});

it('only asks the security resolver when adult content was not requested', function () {
    $this->configure(['detectors.cloudflare.enabled' => true]);

    Http::fake(['*' => Http::response(dnsAnswer('ok.test', '93.184.216.34'))]);

    expect(SafeUrl::isSafe('ok.test', 'malware'))->toBeTrue();

    Http::assertSentCount(1);
    Http::assertSent(fn (Request $r) => str_contains($r->url(), 'security.cloudflare-dns.com'));
});

it('records a provider failure as an error instead of failing the check', function () {
    $this->configure(['detectors.cloudflare.enabled' => true]);

    Http::fake(['*' => Http::response('oops', 502)]);

    $result = SafeUrl::check('whatever.test');

    expect($result->isSafe())->toBeTrue()
        ->and($result->errors)->toHaveKey('cloudflare');
});

it('maps Google Safe Browsing threats to categories', function () {
    $this->configure([
        'detectors.safe_browsing.enabled' => true,
        'detectors.safe_browsing.key' => 'test-key',
    ]);

    Http::fake([
        'safebrowsing.googleapis.com/*' => Http::response(['matches' => [
            ['threatType' => 'SOCIAL_ENGINEERING', 'threat' => ['url' => 'http://phish.test']],
        ]]),
    ]);

    $result = SafeUrl::check('http://phish.test');

    expect($result->isPhishing())->toBeTrue()
        ->and($result->verdict()->detector)->toBe('safe_browsing');

    Http::assertSent(function (Request $r) {
        return str_contains($r->url(), 'key=test-key')
            && $r['threatInfo']['threatTypes'] === ['MALWARE', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION', 'SOCIAL_ENGINEERING']
            && $r['threatInfo']['threatEntries'] === [['url' => 'http://phish.test']];
    });
});

it('skips Safe Browsing when only adult content is requested', function () {
    $this->configure([
        'detectors.safe_browsing.enabled' => true,
        'detectors.safe_browsing.key' => 'test-key',
    ]);

    Http::fake();

    SafeUrl::check('https://example.com', 'adult');

    Http::assertNothingSent();
});

it('caches results but never caches errors', function () {
    $this->configure(['detectors.cloudflare.enabled' => true]);

    Http::fakeSequence()
        ->push('down', 503)
        ->push(dnsAnswer('x.test', '93.184.216.34'))
        ->push(dnsAnswer('x.test', '93.184.216.34'));

    expect(SafeUrl::check('x.test', 'adult')->hasErrors())->toBeTrue();   // 1 request, not cached
    expect(SafeUrl::check('x.test', 'adult')->hasErrors())->toBeFalse();  // 1 request, cached
    expect(SafeUrl::check('x.test', 'adult')->hasErrors())->toBeFalse();  // from cache

    Http::assertSentCount(2);
});

it('runs custom detectors registered at runtime', function () {
    SafeUrl::extend('my-api', new class implements \Rowbird\SafeUrl\Contracts\Detector
    {
        public function categories(): array
        {
            return [\Rowbird\SafeUrl\Enums\Category::Adult];
        }

        public function inspect(\Rowbird\SafeUrl\Support\Inspection $inspection): array
        {
            return $inspection->target->host === 'custom.test'
                ? [new \Rowbird\SafeUrl\Support\Verdict(\Rowbird\SafeUrl\Enums\Category::Adult, 'my-api', 'Flagged by my API')]
                : [];
        }
    });

    expect(SafeUrl::check('custom.test')->verdict()->detector)->toBe('my-api');
});

it('honours the allow and deny lists', function () {
    seedBlocklist(['naughty.test' => 'adult']);
    $this->configure([
        'allow' => ['naughty.test'],
        'deny' => ['denied.test' => 'adult'],
    ]);

    expect(SafeUrl::check('www.naughty.test')->allowlisted)->toBeTrue()
        ->and(SafeUrl::isSafe('www.naughty.test'))->toBeTrue()
        ->and(SafeUrl::check('denied.test')->verdict()->detector)->toBe('deny');
});
