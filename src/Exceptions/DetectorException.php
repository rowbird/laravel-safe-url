<?php

namespace Rowbird\SafeUrl\Exceptions;

use RuntimeException;

/**
 * A detector could not answer (timeout, provider down, bad response).
 * The check carries on with the other detectors and records the error.
 */
class DetectorException extends RuntimeException {}
