<?php
/**
 * Config Exception
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */



namespace WP_Social_Auth;

/**
* Exception thrown for configuration-related errors.
*/
class WP_Social_Auth_Config_Exception extends \Exception
{
	/**
	* Constructor.
	*
	* @param string $message Error message.
	* @param int $code Error code.
	* @param \Throwable|null $previous Previous exception.
	*/
	public function __construct(string $message = 'Invalid WP_Social_Auth_Configuration, int $code = 0, \Throwable $previous = null)
	{
		parent::__construct($message, $code, $previous);
	}
}

