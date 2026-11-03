<?php

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Rowbird\SafeUrl\Facades\SafeUrl;
use Rowbird\SafeUrl\Rules\SafeUrlRule;

beforeEach(function () {
    seedBlocklist([
        'naughty.test' => 'adult',
        'evil.test' => 'malware',
        'casino.test' => 'gambling',
    ]);
});

it('validates with the fluent rule object', function () {
    $rule = SafeUrl::rule()->notAdult();

    $validator = Validator::make(['site' => 'https://naughty.test'], ['site' => ['required', 'url', $rule]]);

    expect($validator->fails())->toBeTrue()
        ->and($validator->errors()->first('site'))->toBe('The site must not link to an adult content website.')
        ->and($rule->result()->isAdult())->toBeTrue();

    // Only adult was asked for, so a malware domain passes this rule.
    expect(Validator::make(['site' => 'https://evil.test'], ['site' => [SafeUrl::rule()->notAdult()]])->passes())->toBeTrue();
});

it('picks the message of the matching category', function () {
    $validator = Validator::make(
        ['a' => 'evil.test', 'b' => 'casino.test'],
        ['a' => [SafeUrlRule::make()->all()], 'b' => [Rule::safeUrl()->notGambling()]],
    );

    expect($validator->errors()->first('a'))->toBe('The a links to a website flagged for malware.')
        ->and($validator->errors()->first('b'))->toBe('The b must not link to a gambling website.');
});

it('supports the string rules', function () {
    $data = ['a' => 'naughty.test', 'b' => 'casino.test', 'c' => 'evil.test', 'd' => 'example.com', 'e' => 'casino.test'];

    $validator = Validator::make($data, [
        'a' => 'safe_url',
        'b' => 'safe_url:adult,gambling',
        'c' => 'not_malware',
        'd' => 'not_adult',
        'e' => 'not_adult',
    ]);

    expect($validator->errors()->toArray())->toBe([
        'a' => ['The a must not link to an adult content website.'],
        'b' => ['The b must not link to a gambling website.'],
        'c' => ['The c links to a website flagged for malware.'],
    ]);
});

it('lets custom messages win', function () {
    $validator = Validator::make(
        ['site' => 'naughty.test', 'other' => 'naughty.test'],
        ['site' => 'not_adult', 'other' => [SafeUrl::rule()->notAdult()]],
        ['site.not_adult' => 'Nope.'],
    );

    expect($validator->errors()->first('site'))->toBe('Nope.');
});

it('translates messages to Brazilian Portuguese', function () {
    app()->setLocale('pt_BR');

    $validator = Validator::make(['site' => 'naughty.test'], ['site' => 'not_adult'], [], ['site' => 'site']);

    expect($validator->errors()->first('site'))->toBe('O campo site não pode apontar para um site de conteúdo adulto.');
});

it('leaves malformed and empty values to the other rules', function (mixed $value) {
    expect(Validator::make(['site' => $value], ['site' => [SafeUrl::rule()->notAdult(), 'not_adult']])->passes())->toBeTrue();
})->with([null, '', 'not a url', 'javascript:alert(1)', 123, [['array']]]);

it('lets unverifiable urls through by default and blocks them in strict mode', function () {
    $this->configure(['detectors.cloudflare.enabled' => true]);
    Http::fake(['*' => Http::response('', 503)]);

    expect(Validator::make(['s' => 'unknown.test'], ['s' => [SafeUrl::rule()->notAdult()]])->passes())->toBeTrue();

    $strict = Validator::make(['s' => 'unknown.test', 't' => 'unknown.test'], [
        's' => [SafeUrl::rule()->notAdult()->strict()],
        't' => 'safe_url:adult,strict',
    ]);

    expect($strict->errors()->first('s'))->toBe('The s could not be verified right now. Please try again.')
        ->and($strict->errors()->first('t'))->toBe('The t could not be verified right now. Please try again.');
});

it('reads fail_closed from the config', function () {
    $this->configure(['detectors.cloudflare.enabled' => true, 'fail_closed' => true]);
    Http::fake(['*' => Http::response('', 503)]);

    expect(Validator::make(['s' => 'unknown.test'], ['s' => 'not_adult'])->fails())->toBeTrue();
});
