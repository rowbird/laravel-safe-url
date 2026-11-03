<?php

namespace Rowbird\SafeUrl\Exceptions;

/**
 * The URL resolves to a private, loopback, link-local or reserved address,
 * so it was not fetched (SSRF protection).
 */
class UnsafeTargetException extends FetchException {}
