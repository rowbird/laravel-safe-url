<?php

namespace Rowbird\SafeUrl\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Exceptions\InvalidUrlException;
use Rowbird\SafeUrl\SafeUrlManager;
use Rowbird\SafeUrl\Support\Result;

/**
 * 'site' => ['required', 'url', SafeUrl::rule()->notAdult()->notMalware()]
 *
 * Values that are not a URL or domain pass through: pair it with `url`
 * (or your own format rule) to reject those.
 */
class SafeUrlRule implements ValidationRule
{
    /** @var list<Category> */
    protected array $categories = [];

    protected ?bool $failClosed = null;

    protected ?Result $lastResult = null;

    public static function make(): static
    {
        return new static;
    }

    public function notAdult(): static
    {
        return $this->add(Category::Adult);
    }

    public function notMalware(): static
    {
        return $this->add(Category::Malware);
    }

    public function notPhishing(): static
    {
        return $this->add(Category::Phishing);
    }

    public function notGambling(): static
    {
        return $this->add(Category::Gambling);
    }

    /**
     * Shortcut for adult + malware + phishing + gambling.
     */
    public function all(): static
    {
        return $this->add(...Category::cases());
    }

    /**
     * Fail validation when a detector could not answer and nothing else
     * flagged the URL, instead of letting it through.
     */
    public function strict(bool $strict = true): static
    {
        $this->failClosed = $strict;

        return $this;
    }

    public function add(Category|string ...$categories): static
    {
        $this->categories = Category::list([...$this->categories, ...$categories]);

        return $this;
    }

    /**
     * @return list<Category>
     */
    public function categories(): array
    {
        return $this->categories;
    }

    /**
     * The result of the last validation run, handy for logging.
     */
    public function result(): ?Result
    {
        return $this->lastResult;
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value) || trim($value) === '') {
            return;
        }

        $manager = app(SafeUrlManager::class);

        try {
            $this->lastResult = $result = $manager->check($value, $this->categories ?: null);
        } catch (InvalidUrlException) {
            return;
        }

        if ($message = static::message($result, $this->failClosed ?? (bool) $manager->config('fail_closed', false))) {
            $fail($message)->translate();
        }
    }

    /**
     * Translation key for a failing result, or null when it passes.
     */
    public static function message(Result $result, bool $failClosed): ?string
    {
        if ($category = $result->category()) {
            return "safe-url::validation.{$category->value}";
        }

        if ($failClosed && $result->hasErrors()) {
            return 'safe-url::validation.unverified';
        }

        return null;
    }
}
