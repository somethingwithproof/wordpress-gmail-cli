<?php

namespace WordPressGmailCli\SocialAuth\Exception;

/**
 * Exception thrown when rate limits are exceeded.
 */
class RateLimitException extends AuthException
{
    /**
     * Constructor.
     *
     * @param string $message Technical error message.
     * @param string $userMessage User-friendly message (safe for display).
     * @param int $code Error code.
     * @param \Throwable|null $previous Previous exception.
     */
    public function __construct(
        string $message = 'Rate limit exceeded', 
        string $userMessage = 'Too many login attempts. Please try again later.',
        int $code = 429, 
        \Throwable $previous = null
    ) {
        parent::__construct($message, $userMessage, $code, $previous);
    }
}

