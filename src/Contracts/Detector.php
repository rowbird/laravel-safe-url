<?php

namespace Rowbird\SafeUrl\Contracts;

use Rowbird\SafeUrl\Enums\Category;
use Rowbird\SafeUrl\Support\Inspection;
use Rowbird\SafeUrl\Support\Verdict;

interface Detector
{
    /**
     * Categories this detector is able to identify. It is skipped when none
     * of them was requested.
     *
     * @return list<Category>
     */
    public function categories(): array;

    /**
     * Return one verdict per match, or an empty array when nothing matched.
     * Throw DetectorException when the detector could not answer.
     *
     * @return list<Verdict>
     */
    public function inspect(Inspection $inspection): array;
}
