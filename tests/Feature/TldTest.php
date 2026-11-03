<?php

use Illuminate\Support\Facades\Validator;
use Rowbird\SafeUrl\Facades\SafeUrl;

it('flags adult top-level domains without any lookup', function (string $url) {
    $result = SafeUrl::check($url);

    expect($result->isAdult())->toBeTrue()
        ->and($result->verdict()->detector)->toBe('tld')
        ->and($result->errors)->toBe([]); // stopped before the (unsynced) blocklist
})->with(['https://site.xxx', 'videos.example.porn', 'WWW.SOMETHING.ADULT/page', 'http://foo.sex.']);

it('does not flag look-alike domains', function (string $url) {
    seedBlocklist(['unrelated.test' => 'adult']);

    expect(SafeUrl::isSafe($url))->toBeTrue();
})->with(['xxx.com', 'sexshop.com.br', 'porn.example.com', 'adultswim.com', 'pornography-research.edu', 'essex.ac.uk']);

it('flags betting TLDs only when gambling is requested', function () {
    seedBlocklist(['unrelated.test' => 'adult']);

    expect(SafeUrl::isSafe('lucky.casino'))->toBeTrue()
        ->and(SafeUrl::check('lucky.casino', 'gambling')->isGambling())->toBeTrue()
        ->and(Validator::make(['s' => 'win.bet'], ['s' => 'not_gambling'])->fails())->toBeTrue();
});

it('accepts custom suffixes, including second-level ones', function () {
    $this->configure(['detectors.tld.suffixes' => ['.sex.pl' => 'adult', 'xxx' => ['adult']]]);

    expect(SafeUrl::check('foo.sex.pl')->isAdult())->toBeTrue()
        ->and(SafeUrl::check('a.xxx')->isAdult())->toBeTrue()
        ->and(SafeUrl::check('a.porn')->hasErrors())->toBeTrue(); // .porn removed, falls through to the blocklist
});

it('can be disabled', function () {
    $this->configure(['detectors.tld.enabled' => false]);

    expect(SafeUrl::check('site.xxx')->isSafe())->toBeTrue();
});
