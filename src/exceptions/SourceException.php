<?php

declare(strict_types=1);

namespace ruvelo\securityalerts\exceptions;

use RuntimeException;

/**
 * An advisory source could not be reached or answered with something unusable.
 */
class SourceException extends RuntimeException
{
}
