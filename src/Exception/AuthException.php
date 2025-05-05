<?php

namespace WordPressGmailCli\SocialAuth\Exception;

/**
 * Exception thrown for authentication-related errors.
 */
class AuthException extends \Exception
{
    /**
     * A user-friendly message that can be safely displayed to users.
     *
     * @var string
     */
    protected $userMessage;

    /**
     * Constructor.
     *
     * @param string $message Technical error message.
     * @param string $userMessage User-friendly message (safe for display).
     * @param int $code Error code.
     * @param \Throwable|null $previous Previous exception.
     */
    public function __construct(string $message = '', string $userMessage = '', int $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->userMessage = $userMessage ?: 'Authentication failed. Please try again.';
    }

    /**
     * Get the user-friendly error message.
     *
     * @return string User-friendly error message.
     */
    public function getUserMessage(): string
    {
        return $this->userMessage;
    }
}

