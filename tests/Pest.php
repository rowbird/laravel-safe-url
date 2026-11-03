<?php

use Rowbird\SafeUrl\Blocklist\BlocklistStore;
use Rowbird\SafeUrl\Tests\TestCase;

uses(TestCase::class)->in('Feature');

/**
 * @param  array<string, string>  $domains  domain => category
 */
function seedBlocklist(array $domains): void
{
    app(BlocklistStore::class)->rebuild(
        (function () use ($domains) {
            foreach ($domains as $domain => $category) {
                yield [$domain, $category, 'test-list'];
            }
        })()
    );
}
