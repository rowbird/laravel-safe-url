# Changelog

## 0.1.0 - Unreleased

- `safe_url`, `not_adult`, `not_malware`, `not_phishing`, `not_gambling` string rules and the fluent `SafeUrl::rule()` / `Rule::safeUrl()`.
- Detectors: adult and gambling top-level domains (.xxx, .porn, .adult, .sex, .casino, .poker, .bet), offline blocklist (SQLite), Cloudflare for Families DNS, Google Safe Browsing, page content (RTA label, meta rating, keywords).
- Redirect following with SSRF protection.
- `safe-url:sync` and `safe-url:check` commands.
- Result caching, allow/deny lists, `UnsafeUrlDetected` event, `SafeUrl::fake()`.
- English and Brazilian Portuguese translations.
- A source that fails during `safe-url:sync` keeps the domains it already had.
- Backslashes in a URL are read the way browsers read them.
- SSRF guard also refuses NAT64, 6to4, Teredo, site-local and IPv4-compatible IPv6 addresses.
