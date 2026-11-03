<?php

namespace Rowbird\SafeUrl\Detectors;

use Rowbird\SafeUrl\Contracts\Detector;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Exceptions\DetectorException;
use Rowbird\SafeUrl\Http\FetchedPage;
use Rowbird\SafeUrl\Support\Inspection;
use Rowbird\SafeUrl\Support\Verdict;

/**
 * Looks at the page itself for self-declared adult markers:
 *
 *  - the RTA label (Restricted To Adults), as a meta tag or a Rating header
 *  - <meta name="rating" content="adult|mature|restricted|explicit">
 *  - optional keyword heuristic over title / description / keywords
 */
final class ContentDetector implements Detector
{
    public const RTA_LABEL = 'RTA-5042-1996-1400-1577-RTA';

    private const ADULT_RATINGS = ['adult', 'mature', 'restricted', 'explicit', 'rta', '18+', 'xxx'];

    /**
     * @param  array{keywords?: list<string>, keyword_threshold?: int}  $config
     */
    public function __construct(private readonly array $config = []) {}

    public function categories(): array
    {
        return [Category::Adult];
    }

    public function inspect(Inspection $inspection): array
    {
        $page = $inspection->page();

        if ($page === null) {
            throw new DetectorException('Page not fetched: '.($inspection->fetchError() ?? 'unknown error'));
        }

        $reason = $this->reason($page);

        return $reason === null ? [] : [new Verdict(Category::Adult, 'content', $reason, $page->url)];
    }

    public function reason(FetchedPage $page): ?string
    {
        $header = $page->header('rating');

        if ($header !== null && stripos($header, self::RTA_LABEL) !== false) {
            return 'RTA label in the Rating header';
        }

        if (! $page->isHtml()) {
            return null;
        }

        $head = $this->head($page->body);
        $meta = $this->metaTags($head);

        foreach ($meta as $name => $values) {
            if (! in_array($name, ['rating', 'pics-label'], true)) {
                continue;
            }

            foreach ($values as $value) {
                if (stripos($value, self::RTA_LABEL) !== false) {
                    return 'RTA label in <meta name="rating">';
                }

                if (in_array(strtolower(trim($value)), self::ADULT_RATINGS, true)) {
                    return "<meta name=\"rating\" content=\"{$value}\">";
                }
            }
        }

        return $this->keywordReason($head, $meta);
    }

    /**
     * @param  array<string, list<string>>  $meta
     */
    private function keywordReason(string $head, array $meta): ?string
    {
        $keywords = array_filter(array_map('strtolower', $this->config['keywords'] ?? []));

        if ($keywords === []) {
            return null;
        }

        preg_match('~<title[^>]*>(.*?)</title>~is', $head, $title);

        $text = mb_strtolower(html_entity_decode(implode(' ', [
            $title[1] ?? '',
            ...($meta['description'] ?? []),
            ...($meta['keywords'] ?? []),
            ...($meta['og:title'] ?? []),
            ...($meta['og:description'] ?? []),
        ]), ENT_QUOTES | ENT_HTML5));

        $hits = [];

        foreach ($keywords as $keyword) {
            if (preg_match('/(?<![\p{L}\p{N}])'.preg_quote($keyword, '/').'(?![\p{L}\p{N}])/u', $text)) {
                $hits[] = $keyword;
            }
        }

        $threshold = max(1, (int) ($this->config['keyword_threshold'] ?? 2));

        return count($hits) >= $threshold
            ? 'Adult keywords in title/description: '.implode(', ', $hits)
            : null;
    }

    private function head(string $html): string
    {
        $end = stripos($html, '</head>');

        return $end === false ? $html : substr($html, 0, $end);
    }

    /**
     * @return array<string, list<string>> lower-cased name/property/http-equiv => contents
     */
    private function metaTags(string $html): array
    {
        $out = [];

        preg_match_all('~<meta\b([^>]*)>~i', $html, $tags);

        foreach ($tags[1] as $attributes) {
            preg_match_all('~([a-z:-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~i', $attributes, $pairs, PREG_SET_ORDER);

            $attrs = [];
            foreach ($pairs as $pair) {
                $attrs[strtolower($pair[1])] = $pair[2] !== '' ? $pair[2] : (($pair[3] ?? '') !== '' ? $pair[3] : ($pair[4] ?? ''));
            }

            $name = strtolower($attrs['name'] ?? $attrs['property'] ?? $attrs['http-equiv'] ?? '');

            if ($name !== '' && isset($attrs['content'])) {
                $out[$name][] = $attrs['content'];
            }
        }

        return $out;
    }
}
