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
 * Google Safe Browsing Lookup API v4.
 */
final class SafeBrowsingDetector implements Detector
{
    private const THREATS = [
        'MALWARE' => Category::Malware,
        'UNWANTED_SOFTWARE' => Category::Malware,
        'POTENTIALLY_HARMFUL_APPLICATION' => Category::Malware,
        'SOCIAL_ENGINEERING' => Category::Phishing,
    ];

    /**
     * @param  array{key?: ?string, endpoint?: string, client_id?: string, timeout?: int}  $config
     */
    public function __construct(
        private readonly HttpFactory $http,
        private readonly array $config = [],
    ) {}

    public function categories(): array
    {
        return [Category::Malware, Category::Phishing];
    }

    public function inspect(Inspection $inspection): array
    {
        if (empty($this->config['key'])) {
            throw new DetectorException('Google Safe Browsing key is missing (SAFE_URL_GOOGLE_KEY).');
        }

        $threatTypes = array_keys(array_filter(
            self::THREATS,
            fn (Category $category) => $inspection->wants($category),
        ));

        $entries = array_map(fn ($t) => ['url' => $t->url], $inspection->targets());

        try {
            $response = $this->http
                ->timeout((int) ($this->config['timeout'] ?? 3))
                ->asJson()
                ->post(($this->config['endpoint'] ?? 'https://safebrowsing.googleapis.com/v4/threatMatches:find').'?key='.urlencode($this->config['key']), [
                    'client' => [
                        'clientId' => $this->config['client_id'] ?? 'laravel-safe-url',
                        'clientVersion' => '1.0',
                    ],
                    'threatInfo' => [
                        'threatTypes' => $threatTypes,
                        'platformTypes' => ['ANY_PLATFORM'],
                        'threatEntryTypes' => ['URL'],
                        'threatEntries' => $entries,
                    ],
                ]);
        } catch (ConnectionException $e) {
            throw new DetectorException("Google Safe Browsing unreachable: {$e->getMessage()}", previous: $e);
        }

        if (! $response->successful()) {
            throw new DetectorException("Google Safe Browsing returned HTTP {$response->status()}.");
        }

        $verdicts = [];

        foreach ($response->json('matches') ?? [] as $match) {
            $category = self::THREATS[$match['threatType'] ?? ''] ?? null;

            if ($category !== null) {
                $verdicts[] = new Verdict($category, 'safe_browsing', "Google Safe Browsing: {$match['threatType']}", $match['threat']['url'] ?? null);
            }
        }

        return $verdicts;
    }
}
