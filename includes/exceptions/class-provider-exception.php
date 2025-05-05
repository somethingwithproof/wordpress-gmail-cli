<?php
/**
 * Provider Exception
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */



namespace WP_Social_Auth;

/**
* Exception thrown for provider-specific errors.
*/
class WP_Social_Auth_Provider_Exception extends AuthException
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
		string $message = '', 
		string $userMessage = 'Authentication provider error. Please try again later.',
		int $code = 0, 
		\Throwable $previous = null
	) {
		parent::__construct($message, $userMessage, $code, $previous);
	}
}

