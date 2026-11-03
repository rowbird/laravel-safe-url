<?php

namespace Rowbird\SafeUrl\Console;

use Illuminate\Console\Command;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Exceptions\InvalidUrlException;
use Rowbird\SafeUrl\SafeUrlManager;

class CheckCommand extends Command
{
    protected $signature = 'safe-url:check
        {url : URL or domain to check}
        {--category=* : Categories to check (adult, malware, phishing, gambling)}
        {--all : Check every category}
        {--json : Print the result as JSON}';

    protected $description = 'Check a URL against the configured detectors';

    public function handle(SafeUrlManager $manager): int
    {
        $categories = $this->option('all')
            ? Category::cases()
            : ($this->option('category') ?: null);

        try {
            $result = $manager->check((string) $this->argument('url'), $categories);
        } catch (InvalidUrlException $e) {
            $this->components->error($e->getMessage());

            return self::INVALID;
        }

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return $result->isSafe() ? self::SUCCESS : self::FAILURE;
        }

        $this->components->twoColumnDetail('Host', $result->host);
        $this->components->twoColumnDetail('Checked', implode(', ', array_map(fn ($c) => $c->value, $result->checked)));

        if ($result->allowlisted) {
            $this->components->info('Allowlisted.');
        }

        foreach ($result->verdicts as $verdict) {
            $this->components->twoColumnDetail(
                "<fg=red>{$verdict->category->value}</> via {$verdict->detector}",
                trim($verdict->reason.' '.($verdict->matched ? "({$verdict->matched})" : '')),
            );
        }

        foreach ($result->errors as $detector => $error) {
            $this->components->warn("{$detector}: {$error}");
        }

        $result->isSafe()
            ? $this->components->info($result->hasErrors() ? 'Nothing found, but some detectors could not answer.' : 'Safe.')
            : $this->components->error('Unsafe.');

        return $result->isSafe() ? self::SUCCESS : self::FAILURE;
    }
}
