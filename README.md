# Laravel Safe URL

Validation rules that keep adult, malware, phishing and gambling links out of your app.

```php
$request->validate([
    'website' => ['required', 'url', 'not_adult'],
]);
```

Laravel's `url` and `active_url` tell you a link is well formed and resolves. This package tells you **what is on the other side**, by combining several sources so no single provider is a point of failure:

| Detector | What it catches | Cost | Default |
| --- | --- | --- | --- |
| **Top-level domain** (`.xxx`, `.porn`, `.adult`, `.sex`) | adult, gambling | none | on |
| **Blocklist** | adult, gambling, phishing, malware | offline, ~20 µs per lookup | on |
| **Cloudflare for Families** (DNS-over-HTTPS) | adult, malware | free, no key, 1–2 requests | on |
| **Google Safe Browsing** | malware, phishing | free key | on when a key is set |
| **Page content** (RTA label, `<meta name="rating">`, keywords) | adult | one request to the URL | off |

Every check is cached, a provider outage never blocks your forms unless you ask it to, and outbound requests to user-supplied URLs are guarded against SSRF.

## Installation

```bash
composer require rowbird/laravel-safe-url
php artisan safe-url:sync
```

`safe-url:sync` downloads the blocklists into a SQLite file under `storage/safe-url` (about 1.4M domains, ~50 MB, a few seconds). Keep it fresh with the scheduler:

```php
// routes/console.php
Schedule::command('safe-url:sync')->daily();
```

Requires PHP 8.2+, Laravel 11, 12 or 13 and `ext-pdo_sqlite`. `ext-intl` is recommended for internationalized domains.

Optionally publish the config and translations:

```bash
php artisan vendor:publish --tag=safe-url-config
php artisan vendor:publish --tag=safe-url-lang
```

## Validation

### String rules

```php
'website' => 'url|safe_url',                  // categories from config (adult, malware, phishing)
'website' => 'url|safe_url:adult,gambling',   // pick the categories
'website' => 'url|not_adult',                 // shortcuts: not_adult, not_malware, not_phishing, not_gambling
'website' => 'url|safe_url:adult,strict',     // fail when it cannot be verified (see below)
```

### Rule object

```php
use Rowbird\SafeUrl\Facades\SafeUrl;
use Illuminate\Validation\Rule;

'website' => ['required', 'url', SafeUrl::rule()->notAdult()->notGambling()],
'website' => ['required', 'url', Rule::safeUrl()->all()->strict()],
```

Values that are not a URL or a domain pass these rules untouched, so pair them with `url` (or your own format rule). Bare domains such as `example.com` are accepted and checked.

The error message names the category that matched:

> The website must not link to an adult content website.

English and Brazilian Portuguese ship with the package. Custom messages work as usual (`'website.not_adult' => '...'`).

## Checking in code

```php
use Rowbird\SafeUrl\Facades\SafeUrl;

SafeUrl::isSafe('https://example.com');      // true
SafeUrl::isAdult('pornhub.com');             // true

$result = SafeUrl::check('https://bit.ly/abc', ['adult', 'phishing']);

$result->isUnsafe();        // bool
$result->categories();      // [Category::Adult]
$result->verdict();         // detector, reason and matched domain
$result->errors;            // ['cloudflare' => 'Cloudflare family DNS unreachable: ...']
$result->isInconclusive();  // nothing found, but a detector failed
```

From the terminal:

```bash
php artisan safe-url:check pornhub.com --all
php artisan safe-url:check https://example.com --json
```

An `Rowbird\SafeUrl\Events\UnsafeUrlDetected` event is dispatched for every match, handy for logging or moderation queues.

## How the detectors work

**Top-level domain.** `.xxx`, `.porn`, `.adult` and `.sex` exist specifically for adult content, so anything under them is flagged without any lookup; `.casino`, `.poker` and `.bet` are flagged as gambling. Add your own suffixes, second-level ones included:

```php
'tld' => [
    'suffixes' => [
        'xxx' => 'adult',
        'sex.pl' => 'adult',
        // ...
    ],
],
```

**Blocklist.** Domain lists in plain, hosts-file or Adblock format (gzip too) are merged into one SQLite file and looked up by primary key: the host and each parent domain, so `cdn.videos.site.com` matches a listing for `site.com`. The defaults come from [The Block List Project](https://github.com/blocklistproject/Lists). If a source fails during a sync, it keeps the domains it already had and the command exits with an error. Add your own lists, remote or local, in `config/safe-url.php`:

```php
'sources' => [
    ['category' => 'adult', 'url' => 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt'],
    ['category' => 'adult', 'path' => resource_path('blocklists/my-list.txt')],
],
```

**Cloudflare for Families.** Cloudflare runs two public resolvers that answer `0.0.0.0` for blocked domains: `1.1.1.2` blocks malware, `1.1.1.3` blocks malware and adult content. A domain blocked by the family resolver but not by the security one is classified as adult; blocked by both, as malware. Queries go over DNS-over-HTTPS, so no special DNS setup is needed.

**Google Safe Browsing.** Set `SAFE_URL_GOOGLE_KEY` to enable it. Note that Google offers the Safe Browsing Lookup API for non-commercial use; for commercial products, Google points to its Web Risk API, which you can plug in as a [custom detector](#custom-detectors).

**Page content.** Opt in with `SAFE_URL_CONTENT=true`. The page is downloaded (first 512 KB) and checked for the [RTA label](https://www.rtalabel.org/) in a meta tag or `Rating` header and for adult `<meta name="rating">` values. You can add a keyword heuristic over the title and description:

```php
'content' => [
    'enabled' => true,
    'keywords' => ['xxx', 'porn', 'nsfw', 'onlyfans'],
    'keyword_threshold' => 2,
],
```

### Shorteners and redirects

With `SAFE_URL_FOLLOW_REDIRECTS=true`, the URL is fetched once and every domain in the redirect chain goes through the host-based detectors, so `bit.ly/xyz` pointing to a blocked site is caught.

### SSRF protection

Whenever the package makes a request to a user-supplied URL (content detector, redirects), each hop is resolved first and refused if any address is private, loopback, link-local, CGNAT, multicast or reserved, including IPv4-mapped IPv6. The connection is pinned to the checked IP to prevent DNS rebinding, redirects are followed manually (3 by default) and the body is capped.

### When a provider is down

By default a detector error does not fail validation: the error is recorded on the result and the other detectors still run. Set `SAFE_URL_FAIL_CLOSED=true`, or use `->strict()` / `safe_url:...,strict` on a single rule, to reject URLs that could not be verified. Results with errors are never cached.

### Allow and deny lists

```php
'allow' => ['mycompany.com'],                // never flagged, subdomains included
'deny'  => ['some-bad-site.com' => 'adult'],
```

## Custom detectors

Implement `Rowbird\SafeUrl\Contracts\Detector` and register it in the config:

```php
'detectors' => [
    // ...
    'web_risk' => ['class' => App\SafeUrl\WebRiskDetector::class, 'key' => env('WEB_RISK_KEY')],
],
```

The class receives its config array as `$config` and anything else from the container. Or at runtime: `SafeUrl::extend('my-api', new MyDetector)`.

```php
use Rowbird\SafeUrl\Contracts\Detector;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Support\Inspection;
use Rowbird\SafeUrl\Support\Verdict;

class MyDetector implements Detector
{
    public function categories(): array
    {
        return [Category::Adult];
    }

    public function inspect(Inspection $inspection): array
    {
        $host = $inspection->target->host;

        return $this->looksAdult($host)
            ? [new Verdict(Category::Adult, 'my-api', 'Flagged by my API', $host)]
            : [];
    }
}
```

Throw `Rowbird\SafeUrl\Exceptions\DetectorException` when your provider cannot answer.

## Testing your app

```php
use Rowbird\SafeUrl\Facades\SafeUrl;

$fake = SafeUrl::fake([
    'naughty.test' => 'adult',
    'evil.test' => ['malware', 'phishing'],
]);

$this->post('/profile', ['website' => 'https://naughty.test'])
    ->assertSessionHasErrors('website');

$fake->assertChecked('https://naughty.test');
```

The fake makes no network calls and needs no synced blocklist.

## Limitations

No source is complete. Lists lag behind new domains, Cloudflare's categorization is its own, and a page can hide what it is. Treat this as a strong filter, not a guarantee, and keep a way for users to report what slips through.

## Contributing

```bash
composer install
composer test
```

## License

MIT. Blocklists downloaded at runtime keep their own licenses.
