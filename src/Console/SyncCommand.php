<?php

namespace Rowbird\SafeUrl\Console;

use Illuminate\Console\Command;
use Rowbird\SafeUrl\Blocklist\BlocklistStore;
use Rowbird\SafeUrl\Blocklist\BlocklistSyncer;
use Rowbird\SafeUrl\SafeUrlManager;
use Throwable;

class SyncCommand extends Command
{
    protected $signature = 'safe-url:sync';

    protected $description = 'Download the configured blocklists and rebuild the local blocklist database';

    public function handle(BlocklistSyncer $syncer, BlocklistStore $store, SafeUrlManager $manager): int
    {
        $this->components->info('Syncing blocklists into '.$store->path());

        try {
            $report = $syncer->sync(function (string $source, ?int $domains, ?string $error) {
                $error === null
                    ? $this->components->twoColumnDetail($source, '<fg=green>'.number_format($domains).' domains</>')
                    : $this->components->twoColumnDetail($source, "<fg=red>failed: {$error}</>");
            });
        } catch (Throwable $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }

        try {
            $manager->flushCache();
        } catch (Throwable $e) {
            $this->components->warn('Blocklist updated, but the cache could not be flushed: '.$e->getMessage());
        }

        $this->newLine();
        foreach ($store->stats()['counts'] as $category => $count) {
            $this->components->twoColumnDetail(ucfirst($category), number_format($count));
        }

        $failed = count(array_filter($report['sources'], fn ($s) => $s['error'] !== null));
        $this->newLine();
        $this->components->info(number_format($report['inserted']).' unique entries stored.'.($failed ? " {$failed} source(s) failed." : ''));

        return $failed ? self::FAILURE : self::SUCCESS;
    }
}
