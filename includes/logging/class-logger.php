<?php
/**
 * Logger
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */



namespace WP_Social_Auth;

use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;

/**
* PSR-3 compatible logger implementation for WordPress.
*/
class WP_Social_Auth_Logger extends AbstractLogger
{
	/**
	* Plugin identifier for log messages.
	*
	* @var string
	*/
	private string $identifier;

	/**
	* Minimum log level to record.
	*
	* @var string
	*/
	private string $minimumLevel;

	/**
	* Map of PSR-3 log levels to their severity values.
	*
	* @var array<string, int>
	*/
	private const LOG_LEVEL_SEVERITY = [
		LogLevel::DEBUG     => 0,
		LogLevel::INFO      => 1,
		LogLevel::NOTICE    => 2,
		LogLevel::WARNING   => 3,
		LogLevel::ERROR     => 4,
		LogLevel::CRITICAL  => 5,
		LogLevel::ALERT     => 6,
		LogLevel::EMERGENCY => 7,
	];

	/**
	* Constructor.
	*
	* @param string $identifier Plugin identifier for log messages.
	* @param string $minimumLevel Minimum PSR-3 log level to record.
	*/
	public function __construct(string $identifier = 'wp-social-auth', string $minimumLevel = LogLevel::INFO)
	{
		$this->identifier = $identifier;
		$this->minimumLevel = $minimumLevel;

		// If we're in debug mode, lower the minimum level
		if (defined('WP_DEBUG') && WP_DEBUG && $minimumLevel === LogLevel::INFO) {
			$this->minimumLevel = LogLevel::DEBUG;
		}
	}

	/**
	* {@inheritdoc}
	*/
	public function log($level, $message, array $context = []): void
	{
		// Skip logging if WP_DEBUG is not enabled and level is below WARNING
		if (!$this->isDebugEnabled() && self::LOG_LEVEL_SEVERITY[$level] < self::LOG_LEVEL_SEVERITY[LogLevel::WARNING]) {
			return;
		}

		// Skip if message level is below minimum level
		if (!$this->isLevelLogged($level)) {
			return;
		}

		// Format the log message
		$formattedMessage = $this->formatMessage($level, $message, $context);

		// Determine logging destination based on WordPress WP_Social_Auth_Configurationthis->writeLog($formattedMessage);
	}

	/**
	* Write the log message to the appropriate destination.
	*
	* @param string $message Formatted log message.
	* @return void
	*/
	private function writeLog(string $message): void
	{
		// Check if WP_DEBUG_LOG is defined
		if (defined('WP_DEBUG_LOG')) {
			if (is_string(WP_DEBUG_LOG)) {
				// Log to custom file path
				error_log($message . PHP_EOL, 3, WP_DEBUG_LOG);
			} elseif (WP_DEBUG_LOG === true) {
				// Log to default debug.log file
				error_log($message);
			} else {
				// WP_DEBUG_LOG is false, use PHP error log
				error_log($message);
			}
		} else {
			// No specific log file defined, use PHP error log
			error_log($message);
		}
	}

	/**
	* Check if debug logging is enabled.
	*
	* @return bool True if debug logging is enabled.
	*/
	private function isDebugEnabled(): bool
	{
		return defined('WP_DEBUG') && WP_DEBUG;
	}

	/**
	* Check if the given level should be logged based on minimum level setting.
	*
	* @param string $level PSR-3 log level.
	* @return bool True if the level should be logged.
	*/
	private function isLevelLogged(string $level): bool
	{
		// Always log errors and above, regardless of minimum level
		if (self::LOG_LEVEL_SEVERITY[$level] >= self::LOG_LEVEL_SEVERITY[LogLevel::ERROR]) {
			return true;
		}

		return self::LOG_LEVEL_SEVERITY[$level] >= self::LOG_LEVEL_SEVERITY[$this->minimumLevel];
	}

	/**
	* Format a log message with context.
	*
	* @param string $level PSR-3 log level.
	* @param string $message Log message.
	* @param array $context Log context.
	* @return string Formatted log message.
	*/
	private function formatMessage(string $level, string $message, array $context): string
	{
		// Start with timestamp and log level
		$output = sprintf(
			'[%s] %s.%s: %s',
			date('Y-m-d H:i:s'),
			$this->identifier,
			strtoupper($level),
			$this->interpolate($message, $context)
		);

		// Add context as JSON if not empty and not already interpolated
		if (!empty($context)) {
			// Remove keys that were already interpolated
			foreach ($context as $key => $val) {
				if (strpos($message, '{' . $key . '}') !== false) {
					unset($context[$key]);
				}
			}

			// Filter out sensitive data
			$context = $this->sanitizeContext($context);

			// Add remaining context as JSON if not empty
			if (!empty($context)) {
				$output .= ' ' . wp_json_encode($context, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
			}
		}

		return $output;
	}

	/**
	* Interpolate context values into message placeholders.
	*
	* @param string $message Message with optional placeholders.
	* @param array $context Context array for placeholder replacement.
	* @return string Message with replaced placeholders.
	*/
	private function interpolate(string $message, array $context): string
	{
		// Build a replacement array with braces around the context keys
		$replace = [];

		foreach ($context as $key => $val) {
			// Skip non-scalar values for placeholder replacement
			if (is_scalar($val) || (is_object($val) && method_exists($val, '__toString'))) {
				$replace['{' . $key . '}'] = (string) $val;
			}
		}

		// Interpolate replacement values into the message
		return strtr($message, $replace);
	}

	/**
	* Sanitize context data to remove sensitive information.
	*
	* @param array $context Context array to sanitize.
	* @return array Sanitized context array.
	*/
	private function sanitizeContext(array $context): array
	{
		$sensitiveKeys = [
			'password',
			'passwd',
			'pass',
			'pwd',
			'secret',
			'token',
			'access_token',
			'refresh_token',
			'auth',
			'authorization',
			'key',
			'api_key',
			'apikey',
			'client_secret',
			'clientsecret',
			'app_secret'
		];

		foreach ($context as $key => $value) {
			// Check if this is a nested array
			if (is_array($value)) {
				$context[$key] = $this->sanitizeContext($value);
			} elseif (is_scalar($value)) {
				// Check if the current key contains any sensitive keywords
				foreach ($sensitiveKeys as $sensitiveKey) {
					if (stripos($key, $sensitiveKey) !== false) {
						$context[$key] = '***REDACTED***';
						break;
					}
				}
			}
		}

		return $context;
	}

	/**
	* Set the minimum log level.
	*
	* @param string $level PSR-3 log level.
	* @return self
	* @throws \InvalidArgumentException If level is invalid.
	*/
	public function setMinimumLevel(string $level): self
	{
		if (!isset(self::LOG_LEVEL_SEVERITY[$level])) {
			throw new \InvalidArgumentException(
				sprintf('Invalid log level "%s"', $level)
			);
		}

		$this->minimumLevel = $level;
		return $this;
	}

	/**
	* Get the current minimum log level.
	*
	* @return string Current minimum PSR-3 log level.
	*/
	public function getMinimumLevel(): string
	{
		return $this->minimumLevel;
	}

	/**
	* Set the logger identifier.
	* 
	* @param string $identifier Logger identifier.
	* @return self
	*/
	public function setIdentifier(string $identifier): self
	{
		$this->identifier = $identifier;
		return $this;
	}

	/**
	* Get the current logger identifier.
	* 
	* @return string Current logger identifier.
	*/
	public function getIdentifier(): string
	{
		return $this->identifier;
	}
}

