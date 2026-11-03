<?php

namespace Rowbird\SafeUrl\Http;

/**
 * Decides whether an IP address is safe to connect to from the server.
 */
final class IpGuard
{
    /**
     * Ranges PHP's FILTER_FLAG_NO_PRIV_RANGE / NO_RES_RANGE do not cover.
     */
    private const EXTRA_BLOCKED_V4 = [
        '100.64.0.0/10',   // carrier-grade NAT
        '192.0.0.0/24',    // IETF protocol assignments
        '192.0.2.0/24',    // TEST-NET-1
        '198.18.0.0/15',   // benchmarking
        '198.51.100.0/24', // TEST-NET-2
        '203.0.113.0/24',  // TEST-NET-3
        '224.0.0.0/4',     // multicast
    ];

    /**
     * IPv6 ranges that are internal or can carry an IPv4 address to a
     * translator or tunnel, reaching internal IPv4 from a "public" looking IP.
     */
    private const BLOCKED_V6 = [
        '::/8',           // reserved, IPv4-compatible and IPv4-mapped in hex
        '64:ff9b::/96',   // NAT64
        '64:ff9b:1::/48', // local NAT64
        '100::/64',       // discard
        '2001::/32',      // Teredo
        '2001:db8::/32',  // documentation
        '2002::/16',      // 6to4
        'fc00::/7',       // unique local
        'fe80::/10',      // link local
        'fec0::/10',      // site local (deprecated)
        'ff00::/8',       // multicast
    ];

    public static function isPublic(string $ip): bool
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // IPv4-mapped / compatible IPv6 (::ffff:127.0.0.1) → check the IPv4 part.
        if (str_contains($ip, ':') && preg_match('/^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i', $ip, $m)) {
            return self::isPublic($m[1]);
        }

        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            foreach (self::EXTRA_BLOCKED_V4 as $cidr) {
                if (self::inCidr($ip, $cidr)) {
                    return false;
                }
            }

            return true;
        }

        foreach (self::BLOCKED_V6 as $cidr) {
            if (self::inCidrV6($ip, $cidr)) {
                return false;
            }
        }

        return true;
    }

    private static function inCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr);
        $mask = -1 << (32 - (int) $bits);

        return (ip2long($ip) & $mask) === (ip2long($subnet) & $mask);
    }

    private static function inCidrV6(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr);
        $ipBytes = (string) inet_pton($ip);
        $subnetBytes = (string) inet_pton($subnet);
        $bits = (int) $bits;
        $whole = intdiv($bits, 8);

        if (substr($ipBytes, 0, $whole) !== substr($subnetBytes, 0, $whole)) {
            return false;
        }

        $rest = $bits % 8;

        if ($rest === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $rest) & 0xFF;

        return (ord($ipBytes[$whole]) & $mask) === (ord($subnetBytes[$whole]) & $mask);
    }
}
