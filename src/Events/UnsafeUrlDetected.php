<?php

namespace Rowbird\SafeUrl\Events;

use Rowbird\SafeUrl\Support\Result;

/**
 * Dispatched whenever a check finds a match (not for cached results).
 */
final class UnsafeUrlDetected
{
    public function __construct(public readonly Result $result) {}
}
