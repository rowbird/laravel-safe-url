<?php

use Rowbird\SafeUrl\Blocklist\ListParser;

it('reads domains from every supported format', function () {
    $list = <<<'TXT'
    # comment
    ! adblock comment
    [Adblock Plus 2.0]

    plain-domain.com
    0.0.0.0 hosts-entry.com
    127.0.0.1   tabbed.com   # trailing comment
    ||adblock.com^
    ||adblock-path.com/whatever^$third-party
    *.wildcard.com
    UPPER.Example.COM
    0.0.0.0 0.0.0.0
    127.0.0.1 localhost
    ::1 ip6-localhost
    not a domain
    192.168.0.1
    TXT;

    expect(iterator_to_array(ListParser::domains($list), false))->toBe([
        'plain-domain.com',
        'hosts-entry.com',
        'tabbed.com',
        'adblock.com',
        'adblock-path.com',
        'wildcard.com',
        'upper.example.com',
    ]);
});

it('handles windows line endings and gzip', function () {
    $list = "one.com\r\ntwo.com\r\n";

    expect(iterator_to_array(ListParser::domains($list), false))->toBe(['one.com', 'two.com'])
        ->and(iterator_to_array(ListParser::domains(gzencode($list)), false))->toBe(['one.com', 'two.com']);
});
