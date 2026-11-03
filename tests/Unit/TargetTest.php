<?php

use Rowbird\SafeUrl\Support\Target;

it('parses full urls and bare domains', function (string $input, string $host) {
    expect(Target::parse($input)?->host)->toBe($host);
})->with([
    ['https://www.Example.com/path?q=1', 'www.example.com'],
    ['example.com', 'example.com'],
    ['example.com/some/page', 'example.com'],
    ['//cdn.example.com/x.js', 'cdn.example.com'],
    ['http://example.com.:8080/', 'example.com'],
    ['  sub.example.co.uk  ', 'sub.example.co.uk'],
    ['http://93.184.216.34/', '93.184.216.34'],
    ['http://[2606:2800:220:1::]/', '2606:2800:220:1::'],
]);

it('reads backslashes the way browsers do', function (string $input, string $host) {
    expect(Target::parse($input)?->host)->toBe($host);
})->with([
    ['http://evil.test\\@good.test', 'evil.test'],
    ['http://good.test\\@evil.test', 'good.test'],
    ['http:\\\\evil.test\\path', 'evil.test'],
    ['\\\\evil.test', 'evil.test'],
    ['evil.test\\page', 'evil.test'],
    ['https://good.test/?next=\\evil.test', 'good.test'],
    ['https://good.test/#\\evil.test', 'good.test'],
]);

it('converts internationalized domains to punycode', function () {
    expect(Target::parse('https://ação.com.br')?->host)->toBe('xn--ao-siap.com.br');
})->skip(! function_exists('idn_to_ascii'), 'intl not installed');

it('rejects values that are not http(s) urls', function (string $input) {
    expect(Target::parse($input))->toBeNull();
})->with([
    '',
    'not a url',
    'javascript:alert(1)',
    'ftp://example.com',
    'mailto:me@example.com',
    'localhost',
    'http://',
    'http://exa_mple..com',
]);

it('lists the host and its parent domains', function () {
    expect(Target::parse('https://a.b.example.com')->candidates())
        ->toBe(['a.b.example.com', 'b.example.com', 'example.com']);

    expect(Target::parse('http://10.0.0.1')->candidates())->toBe(['10.0.0.1']);
});

it('matches a domain and its subdomains only', function () {
    $target = Target::parse('https://videos.example.com');

    expect($target->matches('example.com'))->toBeTrue()
        ->and($target->matches('videos.example.com'))->toBeTrue()
        ->and($target->matches('ample.com'))->toBeFalse()
        ->and($target->matches('other.com'))->toBeFalse();
});
