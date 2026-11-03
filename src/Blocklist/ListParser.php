<?php

namespace Rowbird\SafeUrl\Blocklist;

use Rowbird\SafeUrl\Support\Target;

/**
 * Reads domains out of the common list formats, line by line:
 *
 *   example.com                  plain domain list
 *   0.0.0.0 example.com          hosts file
 *   ||example.com^               Adblock / uBlock
 *   *.example.com                wildcard (stored as example.com; subdomains match anyway)
 *
 * Comments (#, !) and blank lines are skipped.
 */
final class ListParser
{
    private const IGNORED = ['localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', '0.0.0.0'];

    /**
     * @return \Generator<int, string>
     */
    public static function domains(string $contents): \Generator
    {
        if (str_starts_with($contents, "\x1f\x8b")) {
            $contents = gzdecode($contents) ?: '';
        }

        $length = strlen($contents);
        $offset = 0;

        while ($offset < $length) {
            $end = strpos($contents, "\n", $offset);
            $end = $end === false ? $length : $end;
            $domain = self::parseLine(substr($contents, $offset, $end - $offset));
            $offset = $end + 1;

            if ($domain !== null) {
                yield $domain;
            }
        }
    }

    public static function parseLine(string $line): ?string
    {
        $line = trim($line);

        if ($line === '' || $line[0] === '#' || $line[0] === '!' || $line[0] === '[') {
            return null;
        }

        // Strip trailing comments.
        $line = trim(preg_replace('/\s+#.*$/', '', $line));

        if (str_starts_with($line, '||')) {
            $line = preg_split('~[\^/$]~', substr($line, 2))[0];
        } else {
            $tokens = preg_split('/\s+/', $line);

            if (count($tokens) > 1 && filter_var($tokens[0], FILTER_VALIDATE_IP)) {
                $line = $tokens[1];
            } else {
                $line = $tokens[0];
            }
        }

        $line = ltrim($line, '*.');

        if ($line === '' || in_array(strtolower($line), self::IGNORED, true)) {
            return null;
        }

        $host = Target::normalizeHost($line);

        return $host !== null && ! filter_var($host, FILTER_VALIDATE_IP) ? $host : null;
    }
}
