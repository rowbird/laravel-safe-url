<?php

namespace Rowbird\SafeUrl\Rules;

use Illuminate\Contracts\Validation\Factory;
use Illuminate\Validation\Validator;
use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Exceptions\InvalidUrlException;
use Rowbird\SafeUrl\SafeUrlManager;
use WeakMap;

/**
 * String rules:
 *
 *   'site' => 'url|safe_url'                    default categories from config
 *   'site' => 'url|safe_url:adult,gambling'     specific categories
 *   'site' => 'url|not_adult'                   shortcut
 *   'site' => 'url|safe_url:adult,strict'       fail when it can't be verified
 */
final class StringRules
{
    public const RULES = [
        'safe_url' => null,
        'not_adult' => [Category::Adult],
        'not_malware' => [Category::Malware],
        'not_phishing' => [Category::Phishing],
        'not_gambling' => [Category::Gambling],
    ];

    /** @var WeakMap<Validator, array<string, string>> failing attribute => translation key */
    private static ?WeakMap $failures = null;

    public static function register(Factory $factory): void
    {
        self::$failures ??= new WeakMap;

        foreach (self::RULES as $name => $fixed) {
            $factory->extend($name, function (string $attribute, mixed $value, array $parameters, Validator $validator) use ($fixed) {
                return self::passes($attribute, $value, $parameters, $validator, $fixed);
            });

            $factory->replacer($name, function (string $message, string $attribute, string $rule, array $parameters, Validator $validator) {
                $key = self::$failures[$validator][$attribute] ?? 'safe-url::validation.adult';

                // An inline or app-level custom message wins over ours.
                if ($message !== "validation.{$rule}") {
                    return $message;
                }

                return $validator->getTranslator()->get($key, [
                    'attribute' => $validator->getDisplayableAttribute($attribute),
                ]);
            });
        }
    }

    /**
     * @param  list<string>  $parameters
     * @param  list<Category>|null  $fixed
     */
    private static function passes(string $attribute, mixed $value, array $parameters, Validator $validator, ?array $fixed): bool
    {
        if (! is_string($value) || trim($value) === '') {
            return true;
        }

        $strict = in_array('strict', $parameters, true);
        $parameters = array_values(array_diff($parameters, ['strict']));
        $categories = $fixed ?? ($parameters !== [] ? Category::list($parameters) : null);

        $manager = app(SafeUrlManager::class);

        try {
            $result = $manager->check($value, $categories);
        } catch (InvalidUrlException) {
            return true;
        }

        $key = SafeUrlRule::message($result, $strict || (bool) $manager->config('fail_closed', false));

        if ($key === null) {
            return true;
        }

        $failures = self::$failures[$validator] ?? [];
        $failures[$attribute] = $key;
        self::$failures[$validator] = $failures;

        return false;
    }
}
