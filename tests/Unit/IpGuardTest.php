<?php

use Rowbird\SafeUrl\Http\IpGuard;

it('blocks internal addresses', function (string $ip) {
    expect(IpGuard::isPublic($ip))->toBeFalse();
})->with([
    '127.0.0.1', '10.1.2.3', '172.16.5.4', '192.168.0.10', '169.254.169.254', '0.0.0.0',
    '100.64.0.1', '198.18.0.1', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:7f00:1', '::7f00:1',
    // IPv4 embedded in IPv6: reach internal addresses through a translator or tunnel
    '64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe', '64:ff9b:1::1', '2002:7f00:1::', '2001:0:7f00:1::',
    'fec0::1', 'febf::1', 'FE80::1', '2001:db8::1',
    'not-an-ip',
]);

it('allows public addresses', function (string $ip) {
    expect(IpGuard::isPublic($ip))->toBeTrue();
})->with(['93.184.216.34', '8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '::ffff:8.8.8.8', '2a03:2880::1', '2001:4860:4860::8888', 'fb00::1']);
