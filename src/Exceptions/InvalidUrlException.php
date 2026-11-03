<?php

namespace Rowbird\SafeUrl\Exceptions;

use InvalidArgumentException;

class InvalidUrlException extends InvalidArgumentException
{
    public static function for(string $value): self
    {
        return new self("[{$value}] is not a valid http(s) URL or domain.");
    }
}
