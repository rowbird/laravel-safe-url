<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Default categories
    |--------------------------------------------------------------------------
    |
    | Categories checked by the `safe_url` rule (without parameters) and by
    | SafeUrl::check() when no category is given. Available: adult,
    | malware, phishing, gambling.
    |
    */

    'categories' => ['adult', 'malware', 'phishing'],

    /*
    |--------------------------------------------------------------------------
    | Detectors
    |--------------------------------------------------------------------------
    |
    | Detectors run in the order below, cheapest first. Each one only runs
    | when it can answer at least one of the requested categories. Add your
    | own by giving it a name and a `class` implementing
    | Rowbird\SafeUrl\Contracts\Detector.
    |
    */

    'detectors' => [

        // Top-level domains (or any suffix) that exist for a category. No
        // lookup at all. .xxx, .porn, .adult and .sex were created for adult
        // content; .casino, .poker and .bet are betting/gaming TLDs. Add your
        // own suffixes, e.g. 'sex.pl' => 'adult'.
        'tld' => [
            'enabled' => env('SAFE_URL_TLD', true),
            'suffixes' => [
                'xxx' => 'adult',
                'porn' => 'adult',
                'adult' => 'adult',
                'sex' => 'adult',
                'casino' => 'gambling',
                'poker' => 'gambling',
                'bet' => 'gambling',
            ],
        ],

        // Offline lookup against lists downloaded by `php artisan safe-url:sync`.
        'blocklist' => [
            'enabled' => env('SAFE_URL_BLOCKLIST', true),
            'path' => env('SAFE_URL_BLOCKLIST_PATH', storage_path('safe-url/blocklist.sqlite')),
        ],

        // Cloudflare for Families over DNS-over-HTTPS. Free, no key. A domain
        // blocked by the "family" resolver but not by the "security" one is
        // classified as adult; blocked by both, as malware.
        'cloudflare' => [
            'enabled' => env('SAFE_URL_CLOUDFLARE', true),
            'family_endpoint' => 'https://family.cloudflare-dns.com/dns-query',
            'security_endpoint' => 'https://security.cloudflare-dns.com/dns-query',
            'timeout' => 3,
        ],

        // Google Safe Browsing Lookup API v4 (malware and phishing only).
        // Google allows it for non-commercial use; commercial products should
        // look at Google Web Risk instead.
        'safe_browsing' => [
            'enabled' => env('SAFE_URL_GOOGLE_KEY') !== null,
            'key' => env('SAFE_URL_GOOGLE_KEY'),
            'endpoint' => 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
            'client_id' => env('APP_NAME', 'laravel-safe-url'),
            'timeout' => 3,
        ],

        // Downloads the page and looks for self-declared adult markers (the RTA
        // label, <meta name="rating">). Opt-in: it makes an outbound request
        // to a user-supplied URL, guarded against private addresses.
        'content' => [
            'enabled' => env('SAFE_URL_CONTENT', false),

            // Optional keyword heuristic over <title> and meta description /
            // keywords. Off while the list is empty.
            'keywords' => [],
            'keyword_threshold' => 2,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Allow and deny lists
    |--------------------------------------------------------------------------
    |
    | Domains in `allow` (and their subdomains) are always considered safe.
    | `deny` maps a domain to the category it should be flagged as.
    |
    */

    'allow' => [
        // 'example.com',
    ],

    'deny' => [
        // 'some-bad-site.com' => 'adult',
    ],

    /*
    |--------------------------------------------------------------------------
    | Behaviour
    |--------------------------------------------------------------------------
    |
    | fail_closed: when a detector cannot answer (timeout, API down) and no
    | other detector flagged the URL, should validation fail? Off by default
    | so an outage at a provider does not block your forms.
    |
    | stop_on_first: stop running detectors after the first match.
    |
    */

    'fail_closed' => env('SAFE_URL_FAIL_CLOSED', false),

    'stop_on_first' => true,

    /*
    |--------------------------------------------------------------------------
    | Outbound requests made to user-supplied URLs
    |--------------------------------------------------------------------------
    |
    | Used by the content detector and when following redirects. Every hop is
    | resolved and refused if it points to a private, loopback, link-local or
    | reserved address, and the connection is pinned to the checked IP.
    |
    | follow_redirects: resolve shorteners (bit.ly & co.) and run the host
    | based detectors against every domain in the redirect chain.
    |
    */

    'http' => [
        'follow_redirects' => env('SAFE_URL_FOLLOW_REDIRECTS', false),
        'max_redirects' => 3,
        'timeout' => 5,
        'connect_timeout' => 3,
        'max_bytes' => 512 * 1024,
        'user_agent' => 'Mozilla/5.0 (compatible; laravel-safe-url; +https://github.com/rowbird/laravel-safe-url)',
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache
    |--------------------------------------------------------------------------
    |
    | Results are cached per URL and category set. Results with detector
    | errors are never cached. Running safe-url:sync invalidates the cache.
    |
    */

    'cache' => [
        'enabled' => env('SAFE_URL_CACHE', true),
        'store' => env('SAFE_URL_CACHE_STORE'),
        'ttl' => 60 * 60 * 24,
        'prefix' => 'safe-url',
    ],

    /*
    |--------------------------------------------------------------------------
    | Blocklist sources
    |--------------------------------------------------------------------------
    |
    | Downloaded by `php artisan safe-url:sync`. Each source needs a category
    | and either a `url` or a local `path`. Plain domain lists, hosts files
    | (0.0.0.0 example.com) and Adblock syntax (||example.com^) are detected
    | automatically, and .gz files are decompressed. Check each list's
    | license before redistributing it.
    |
    | The defaults come from The Block List Project (Unlicense):
    | https://github.com/blocklistproject/Lists
    |
    | Adult + gambling + phishing ≈ 1.4M domains, a ~50 MB SQLite file and
    | about 10 seconds to sync. The malware list adds 2.6M domains (~100 MB);
    | Cloudflare and Safe Browsing already cover malware well.
    |
    */

    'sources' => [
        [
            'category' => 'adult',
            'url' => 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt',
        ],
        [
            'category' => 'gambling',
            'url' => 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/gambling-nl.txt',
        ],
        [
            'category' => 'phishing',
            'url' => 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/phishing-nl.txt',
        ],
        // [
        //     'category' => 'malware',
        //     'url' => 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/malware-nl.txt',
        // ],

        // Your own list, one domain per line:
        // ['category' => 'adult', 'path' => resource_path('blocklists/adult.txt')],
    ],

];
