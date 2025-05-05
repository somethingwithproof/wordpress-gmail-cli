<?php

namespace WordPressGmailCli\SocialAuth\Exception;

/**
 * Exception thrown for configuration-related errors.
 */
class ConfigException extends \Exception
{
    /**
     * Constructor.
     *
     * @param string $message Error message.
     * @param int $code Error code.
     * @param \Throwable|null $previous Previous exception.
     */
    public function __construct(string $message = 'Invalid configuration', int $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}

