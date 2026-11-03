<?php

namespace Rowbird\SafeUrl\Support;

use Rowbird\SafeUrl\Enums\Category;

final class Result
{
    /**
     * @param  list<Verdict>  $verdicts
     * @param  array<string, string>  $errors  detector name => message
     * @param  list<Category>  $checked
     */
    public function __construct(
        public readonly string $url,
        public readonly string $host,
        public readonly array $verdicts = [],
        public readonly array $errors = [],
        public readonly array $checked = [],
        public readonly bool $allowlisted = false,
    ) {}

    public function isSafe(): bool
    {
        return $this->verdicts === [];
    }

    public function isUnsafe(): bool
    {
        return ! $this->isSafe();
    }

    public function is(Category|string $category): bool
    {
        $category = Category::resolve($category);

        foreach ($this->verdicts as $verdict) {
            if ($verdict->category === $category) {
                return true;
            }
        }

        return false;
    }

    public function isAdult(): bool
    {
        return $this->is(Category::Adult);
    }

    public function isMalware(): bool
    {
        return $this->is(Category::Malware);
    }

    public function isPhishing(): bool
    {
        return $this->is(Category::Phishing);
    }

    public function isGambling(): bool
    {
        return $this->is(Category::Gambling);
    }

    /**
     * @return list<Category>
     */
    public function categories(): array
    {
        return Category::list(array_map(fn (Verdict $v) => $v->category, $this->verdicts));
    }

    public function category(): ?Category
    {
        return $this->verdicts[0]->category ?? null;
    }

    public function verdict(): ?Verdict
    {
        return $this->verdicts[0] ?? null;
    }

    public function hasErrors(): bool
    {
        return $this->errors !== [];
    }

    /**
     * Nothing was flagged, but at least one detector could not answer.
     */
    public function isInconclusive(): bool
    {
        return $this->isSafe() && $this->hasErrors();
    }

    /**
     * @param  array{url: string, host: string, verdicts?: list<array{category: string, detector: string, reason: string, matched: ?string}>, errors?: array<string, string>, checked?: list<string>, allowlisted?: bool}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            $data['url'],
            $data['host'],
            array_map(fn (array $v) => new Verdict(
                Category::from($v['category']), $v['detector'], $v['reason'], $v['matched'] ?? null,
            ), $data['verdicts'] ?? []),
            $data['errors'] ?? [],
            Category::list($data['checked'] ?? []),
            $data['allowlisted'] ?? false,
        );
    }

    public function toArray(): array
    {
        return [
            'url' => $this->url,
            'host' => $this->host,
            'safe' => $this->isSafe(),
            'categories' => array_map(fn (Category $c) => $c->value, $this->categories()),
            'verdicts' => array_map(fn (Verdict $v) => $v->toArray(), $this->verdicts),
            'errors' => $this->errors,
            'checked' => array_map(fn (Category $c) => $c->value, $this->checked),
            'allowlisted' => $this->allowlisted,
        ];
    }
}
