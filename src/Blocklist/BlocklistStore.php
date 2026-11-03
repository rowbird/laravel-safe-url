<?php

namespace Rowbird\SafeUrl\Blocklist;

use PDO;
use RuntimeException;

/**
 * SQLite file holding every blocked domain with its category. A primary key
 * lookup on a few candidate domains is a few microseconds even with millions
 * of rows, and it lives outside the app database.
 */
final class BlocklistStore
{
    private ?PDO $pdo = null;

    public function __construct(private readonly string $path) {}

    public function path(): string
    {
        return $this->path;
    }

    public function exists(): bool
    {
        return is_file($this->path) && filesize($this->path) > 0;
    }

    /**
     * Most specific match among the candidate domains, restricted to the
     * given categories.
     *
     * @param  list<string>  $domains
     * @param  list<string>  $categories
     * @return array{domain: string, category: string, source: ?string}|null
     */
    public function lookup(array $domains, array $categories): ?array
    {
        if ($domains === [] || $categories === [] || ! $this->exists()) {
            return null;
        }

        $d = implode(',', array_fill(0, count($domains), '?'));
        $c = implode(',', array_fill(0, count($categories), '?'));

        $statement = $this->pdo()->prepare(
            "SELECT d.domain, d.category, s.name AS source FROM domains d
             LEFT JOIN sources s ON s.id = d.source_id
             WHERE d.domain IN ({$d}) AND d.category IN ({$c})
             ORDER BY length(d.domain) DESC LIMIT 1"
        );
        $statement->execute([...$domains, ...$categories]);

        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return $row ?: null;
    }

    /**
     * @return array{built_at: ?string, counts: array<string, int>}
     */
    public function stats(): array
    {
        if (! $this->exists()) {
            return ['built_at' => null, 'counts' => []];
        }

        $counts = [];
        foreach ($this->pdo()->query('SELECT category, COUNT(*) AS total FROM domains GROUP BY category') as $row) {
            $counts[$row['category']] = (int) $row['total'];
        }

        $builtAt = $this->pdo()->query("SELECT value FROM meta WHERE key = 'built_at'")->fetchColumn();

        return ['built_at' => $builtAt ?: null, 'counts' => $counts];
    }

    /**
     * Every row currently stored for a source, to carry over when that source
     * could not be downloaded.
     *
     * @return iterable<array{0: string, 1: string, 2: string}>
     */
    public function rowsFromSource(string $source): iterable
    {
        if (! $this->exists()) {
            return;
        }

        $statement = $this->pdo()->prepare(
            'SELECT d.domain, d.category FROM domains d
             JOIN sources s ON s.id = d.source_id
             WHERE s.name = ?'
        );
        $statement->execute([$source]);

        while ($row = $statement->fetch(PDO::FETCH_ASSOC)) {
            yield [$row['domain'], $row['category'], $source];
        }
    }

    /**
     * Builds a fresh database next to the current one and swaps it in
     * atomically, so lookups never see a half-written file.
     *
     * @param  iterable<array{0: string, 1: string, 2?: string}>  $rows  [domain, category, source]
     * @return int rows inserted
     */
    public function rebuild(iterable $rows): int
    {
        $dir = dirname($this->path);

        if (! is_dir($dir) && ! @mkdir($dir, 0775, true) && ! is_dir($dir)) {
            throw new RuntimeException("Could not create directory [{$dir}].");
        }

        $tmp = $this->path.'.'.bin2hex(random_bytes(4)).'.tmp';
        $pdo = new PDO('sqlite:'.$tmp, options: [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

        try {
            $pdo->exec('PRAGMA journal_mode = OFF');
            $pdo->exec('PRAGMA synchronous = OFF');
            $pdo->exec('CREATE TABLE domains (domain TEXT NOT NULL, category TEXT NOT NULL, source_id INTEGER, PRIMARY KEY (domain, category)) WITHOUT ROWID');
            $pdo->exec('CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)');
            $pdo->exec('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)');

            $insert = $pdo->prepare('INSERT OR IGNORE INTO domains (domain, category, source_id) VALUES (?, ?, ?)');
            $insertSource = $pdo->prepare('INSERT INTO sources (name) VALUES (?)');
            $sourceIds = [];
            $count = 0;

            $pdo->beginTransaction();
            foreach ($rows as $row) {
                $source = $row[2] ?? null;

                if ($source !== null && ! isset($sourceIds[$source])) {
                    $insertSource->execute([$source]);
                    $sourceIds[$source] = (int) $pdo->lastInsertId();
                }

                $insert->execute([$row[0], $row[1], $source === null ? null : $sourceIds[$source]]);
                $count += $insert->rowCount();

                if ($count % 50000 === 0) {
                    $pdo->commit();
                    $pdo->beginTransaction();
                }
            }
            $pdo->commit();

            $pdo->prepare("INSERT INTO meta (key, value) VALUES ('built_at', ?)")->execute([gmdate('c')]);
            $pdo = null;

            $this->pdo = null;

            if (! @rename($tmp, $this->path)) {
                throw new RuntimeException("Could not move the blocklist into [{$this->path}].");
            }
        } catch (\Throwable $e) {
            $pdo = null;
            @unlink($tmp);

            throw $e;
        }

        return $count;
    }

    private function pdo(): PDO
    {
        return $this->pdo ??= new PDO('sqlite:'.$this->path, options: [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
    }
}
