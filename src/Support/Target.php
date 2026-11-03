<?php

namespace Rowbird\SafeUrl\Support;

/**
 * A normalized URL plus the host the detectors look up.
 */
final class Target
{
    public function __construct(
        public readonly string $url,
        public readonly string $host,
        public readonly string $scheme = 'http',
        public readonly ?int $port = null,
    ) {}

    /**
     * Accepts full URLs and bare domains ("example.com", "www.example.com/path").
     * Returns null when no usable http(s) host can be extracted.
     */
    public static function parse(string $input): ?self
    {
        $input = trim($input);

        if ($input === '' || preg_match('/\s/', $input)) {
            return null;
        }

        $input = self::browserSlashes($input);

        // "mailto:x", "javascript:x", "data:x": a scheme without "//". A port
        // ("localhost:8080") starts with a digit and is not a scheme.
        if (preg_match('~^[a-z][a-z0-9+.-]*:(?!//)(?!\d)~i', $input)) {
            return null;
        }

        if (! preg_match('~^[a-z][a-z0-9+.-]*://~i', $input)) {
            $input = str_starts_with($input, '//') ? 'http:'.$input : 'http://'.$input;
        }

        $parts = parse_url($input);

        if ($parts === false || empty($parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme'] ?? 'http');

        if (! in_array($scheme, ['http', 'https'], true)) {
            return null;
        }

        $host = self::normalizeHost($parts['host']);

        if ($host === null) {
            return null;
        }

        return new self($input, $host, $scheme, $parts['port'] ?? null);
    }

    /**
     * Browsers read "\\" as "/" before the query and fragment, while parse_url
     * does not: "http://evil.test\\@good.test" opens evil.test.
     */
    private static function browserSlashes(string $input): string
    {
        $end = strcspn($input, '?#');

        return str_replace('\\', '/', substr($input, 0, $end)).substr($input, $end);
    }

    public static function normalizeHost(string $host): ?string
    {
        $host = rtrim(strtolower(trim($host, '[]')), '.');

        if ($host === '') {
            return null;
        }

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }

        if (preg_match('/[^\x20-\x7e]/', $host)) {
            if (! function_exists('idn_to_ascii')) {
                return null;
            }

            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

            if ($ascii === false) {
                return null;
            }

            $host = strtolower($ascii);
        }

        if (! str_contains($host, '.') || ! filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return null;
        }

        return $host;
    }

    public function isIp(): bool
    {
        return filter_var($this->host, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * The host and each parent domain, most specific first:
     * a.b.example.com → [a.b.example.com, b.example.com, example.com].
     *
     * @return list<string>
     */
    public function candidates(): array
    {
        if ($this->isIp()) {
            return [$this->host];
        }

        $labels = explode('.', $this->host);
        $out = [];

        while (count($labels) >= 2) {
            $out[] = implode('.', $labels);
            array_shift($labels);
        }

        return $out;
    }

    /**
     * Whether this host equals the given domain or is a subdomain of it.
     */
    public function matches(string $domain): bool
    {
        $domain = self::normalizeHost($domain) ?? strtolower($domain);

        return $this->host === $domain || str_ends_with($this->host, '.'.$domain);
    }

    public function defaultPort(): int
    {
        return $this->port ?? ($this->scheme === 'https' ? 443 : 80);
    }
}
