<?php

namespace Rowbird\SafeUrl\Detectors;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Rowbird\SafeUrl\Contracts\Detector;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Exceptions\DetectorException;
use Rowbird\SafeUrl\Support\Inspection;
use Rowbird\SafeUrl\Support\Verdict;

/**
 * Cloudflare for Families answers 0.0.0.0 for blocked domains:
 *
 *   security (1.1.1.2) blocks malware
 *   family   (1.1.1.3) blocks malware + adult
 *
 * Blocked by family but not by security → adult. Blocked by security → malware.
 */
final class CloudflareDnsDetector implements Detector
{
    /**
     * @param  array{family_endpoint?: string, security_endpoint?: string, timeout?: int}  $config
     */
    public function __construct(
        private readonly HttpFactory $http,
        private readonly array $config = [],
    ) {}

    public function categories(): array
    {
        return [Category::Adult, Category::Malware];
    }

    public function inspect(Inspection $inspection): array
    {
        $wantsAdult = $inspection->wants(Category::Adult);
        $wantsMalware = $inspection->wants(Category::Malware);

        foreach ($inspection->targets() as $target) {
            if ($target->isIp()) {
                continue;
            }

            if ($wantsAdult && ! $this->blocked('family', $target->host)) {
                // Family blocks a superset of security: nothing to find here.
                continue;
            }

            $malware = $this->blocked('security', $target->host);

            if ($malware && $wantsMalware) {
                return [new Verdict(Category::Malware, 'cloudflare', 'Blocked by Cloudflare security DNS (1.1.1.2)', $target->host)];
            }

            if (! $malware && $wantsAdult) {
                return [new Verdict(Category::Adult, 'cloudflare', 'Blocked by Cloudflare family DNS (1.1.1.3)', $target->host)];
            }
        }

        return [];
    }

    private function blocked(string $resolver, string $host): bool
    {
        $endpoint = $this->config["{$resolver}_endpoint"]
            ?? "https://{$resolver}.cloudflare-dns.com/dns-query";

        try {
            $response = $this->http
                ->accept('application/dns-json')
                ->timeout((int) ($this->config['timeout'] ?? 3))
                ->get($endpoint, ['name' => $host, 'type' => 'A']);
        } catch (ConnectionException $e) {
            throw new DetectorException("Cloudflare {$resolver} DNS unreachable: {$e->getMessage()}", previous: $e);
        }

        if (! $response->successful() || ! is_array($response->json())) {
            throw new DetectorException("Cloudflare {$resolver} DNS returned HTTP {$response->status()}.");
        }

        foreach ($response->json('Answer') ?? [] as $answer) {
            if (($answer['type'] ?? null) === 1 && ($answer['data'] ?? null) === '0.0.0.0') {
                return true;
            }
        }

        return false;
    }
}
