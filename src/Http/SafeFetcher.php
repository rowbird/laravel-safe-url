<?php

namespace Rowbird\SafeUrl\Http;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\RequestException;
use Rowbird\SafeUrl\Contracts\HostResolver;
use Rowbird\SafeUrl\Exceptions\FetchException;
use Rowbird\SafeUrl\Exceptions\UnsafeTargetException;
use Rowbird\SafeUrl\Support\Target;

/**
 * Fetches a user-supplied URL without letting it reach internal services:
 * every hop is resolved, every resolved IP must be public, the connection is
 * pinned to the checked IP (no DNS rebinding), redirects are followed by hand
 * and the body is capped.
 */
final class SafeFetcher
{
    /**
     * @param  array{max_redirects?: int, timeout?: int, connect_timeout?: int, max_bytes?: int, user_agent?: string}  $config
     */
    public function __construct(
        private readonly HttpFactory $http,
        private readonly HostResolver $resolver,
        private readonly array $config = [],
    ) {}

    public function fetch(string $url): FetchedPage
    {
        $maxRedirects = (int) ($this->config['max_redirects'] ?? 3);
        $hops = [];

        for ($i = 0; $i <= $maxRedirects; $i++) {
            $target = Target::parse($url) ?? throw new FetchException("Invalid redirect target [{$url}].");
            $hops[] = $target;
            $ip = $this->publicIpFor($target);

            try {
                $response = $this->http
                    ->withUserAgent($this->config['user_agent'] ?? 'laravel-safe-url')
                    ->accept('text/html,application/xhtml+xml;q=0.9,*/*;q=0.5')
                    ->timeout((int) ($this->config['timeout'] ?? 5))
                    ->connectTimeout((int) ($this->config['connect_timeout'] ?? 3))
                    ->withOptions([
                        'allow_redirects' => false,
                        'stream' => true,
                        'curl' => [CURLOPT_RESOLVE => [$this->pin($target, $ip)]],
                    ])
                    ->get($target->url);
            } catch (ConnectionException|RequestException $e) {
                throw new FetchException("Could not fetch [{$target->url}]: {$e->getMessage()}", previous: $e);
            }

            $status = $response->status();
            $location = $response->header('Location');

            if ($status >= 300 && $status < 400 && $location !== '') {
                $url = self::resolveLocation($target, $location);

                continue;
            }

            [$body, $truncated] = $this->readBody($response->toPsrResponse()->getBody());

            $headers = [];
            foreach ($response->headers() as $name => $values) {
                $headers[strtolower($name)] = array_values((array) $values);
            }

            return new FetchedPage($target->url, $status, $headers, $body, $hops, $truncated);
        }

        throw new FetchException("Too many redirects (more than {$maxRedirects}).");
    }

    private function publicIpFor(Target $target): string
    {
        $ips = $this->resolver->resolve($target->host);

        if ($ips === []) {
            throw new FetchException("Could not resolve [{$target->host}].");
        }

        foreach ($ips as $ip) {
            if (! IpGuard::isPublic($ip)) {
                throw new UnsafeTargetException("Refusing to fetch [{$target->host}]: it resolves to a non-public address.");
            }
        }

        return $ips[0];
    }

    private function pin(Target $target, string $ip): string
    {
        $address = str_contains($ip, ':') ? "[{$ip}]" : $ip;

        return "{$target->host}:{$target->defaultPort()}:{$address}";
    }

    /**
     * @return array{0: string, 1: bool}
     */
    private function readBody(\Psr\Http\Message\StreamInterface $stream): array
    {
        $max = (int) ($this->config['max_bytes'] ?? 512 * 1024);
        $body = '';

        if ($stream->isSeekable()) {
            $stream->rewind();
        }

        while (! $stream->eof() && strlen($body) < $max) {
            $chunk = $stream->read(min(8192, $max - strlen($body)));

            if ($chunk === '') {
                break;
            }

            $body .= $chunk;
        }

        $truncated = ! $stream->eof();

        return [$body, $truncated];
    }

    public static function resolveLocation(Target $base, string $location): string
    {
        $location = trim($location);

        if (preg_match('~^[a-z][a-z0-9+.-]*://~i', $location)) {
            return $location;
        }

        if (str_starts_with($location, '//')) {
            return $base->scheme.':'.$location;
        }

        $port = $base->port ? ':'.$base->port : '';
        $origin = "{$base->scheme}://{$base->host}{$port}";

        if (str_starts_with($location, '/')) {
            return $origin.$location;
        }

        $path = parse_url($base->url, PHP_URL_PATH) ?: '/';
        $dir = substr($path, 0, strrpos($path, '/') + 1);

        return $origin.$dir.$location;
    }
}
