<?php
/**
 * Configuration
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */

namespace WP_Social_Auth;

use WP_Social_Auth\Exceptions\WP_Social_Auth_Config_Exception;

/**
 * Configuration management class for WordPress Social Authentication.
 */
class WP_Social_Auth_Configuration
{
	/**
	 * Configuration values.
	 *
	 * @var array<string, mixed>
	 */
	private array $config = [];

	/**
	 * Default configuration values.
	 *
	 * @var array<string, mixed>
	 */
	private const DEFAULTS = [
		'plugin' => [
			'version' => '1.0.0',
			'min_wp_version' => '5.8',
			'min_php_version' => '7.4',
		],
		],
		'providers' => [
			'google' => [
				'enabled' => true,
				'label' => 'Sign in with Google',
				'client_id' => '',
				'client_secret' => '',
				'hosted_domain' => '',
			],
			'facebook' => [
				'enabled' => false,
				'label' => 'Sign in with Facebook',
				'app_id' => '',
				'app_secret' => '',
			],
		],
		'security' => [
			'rate_limit' => [
				'enabled' => true,
				'max_attempts' => 5,
				'window' => 300, // 5 minutes
			],
			'nonce_lifetime' => 600, // 10 minutes
			'require_verified_email' => true,
		],
		'user' => [
			'registration' => [
				'enabled' => true,
				'default_role' => 'subscriber',
				'update_existing' => true,
			],
			'avatar' => [
				'enabled' => true,
				'download' => true,
			],
			'redirect' => [
				'login' => '',
				'registration' => '',
				'error' => '',
			],
		],
		'logging' => [
			'enabled' => true,
			'level' => 'info', // debug, info, notice, warning, error, critical, alert, emergency
		],
	];

	/**
	* WordPress option prefix for all plugin settings.
	*
	* @var string
	*/
	private const OPTION_PREFIX = 'wp_social_auth_';

	/**
	* Environment variable prefix for configuration.
	*
	* @var string
	*/
	private const ENV_PREFIX = 'WP_SOCIAL_AUTH_';
	/**
	 * Constructor.
	 *
	 * @param array $config Optional configuration override.
	 */
	public function __construct(array $config = [])
	{
		// Start with defaults
		$this->config = self::DEFAULTS;
		
		// Load from WordPress options
		$this->loadFromWordPress();
		
		// Load from environment
		$this->loadFromEnvironment();
		
		// Apply runtime overrides if provided
		if (!empty($config)) {
			$this->config = array_replace_recursive($this->config, $config);
		}
	}
	/**
	 * Get a configuration value.
	 *
	 * @param string $key Configuration key using dot notation (e.g., 'providers.google.client_id').
	 * @param mixed $default Default value if key doesn't exist.
	 * @return mixed Configuration value.
	 */
	public function get(string $key, $default = null)
	{
		$value = $this->getNestedValue($this->config, explode('.', $key));
		return $value ?? $default;
	}
		return $enabled;
	}
w new WP_Social_Auth_Config_Exception(sprintf('Provider "%s" is disabled', $provider));
		}
	* @return mixed Configuration value cast to the specified type.
	*/
	public function getAs(string $key, string $type, $default = null)
	{
		$value = $this->get($key, $default);

		switch ($type) {
			case 'bool':
				return (bool) $value;
			case 'int':
				return (int) $value;
			case 'float':
				return (float) $value;
			case 'string':
				return (string) $value;
			case 'array':
				return (array) $value;
			default:
				return $value;
		}
	}

	/**
	* Check if a configuration value exists.
	*
	* @param string $key Configuration key using dot notation.
	* @return bool True if the key exists.
	*/
	public function has(string $key): bool
	{
		return $this->getNestedValue($this->config, explode('.', $key)) !== null;
	}

	/**
	* Set a configuration value.
	*
	* @param string $key Configuration key using dot notation.
	* @param mixed $value Configuration value.
	* @return self
	*/
	public function set(string $key, $value): self
	{
		$this->setNestedValue($this->config, explode('.', $key), $value);
		return $this;
	}

	/**
	* Get provider-specific configuration.
	*
	* @param string $provider Provider identifier.
	* @return array Provider configuration.
	* @throws ConfigException If provider configuration is invalid or not found.
	*/
	public function getProviderConfig(string $provider): array
	{
		$config = $this->get("providers.{$provider}");

		if (!is_array($config) || empty($config)) {
			throw new WP_Social_Auth_Config_Exceptionsprintf('No configuration found for provider "%s"', $provider));
		}

		// Check if provider is enabled
		if (!($config['enabled'] ?? false)) {
			throw new WP_Social_Auth_Config_Exceptionsprintf('Provider "%s" is disabled', $provider));
		}

		return $config;
	}

	/**
	* Get all enabled providers.
	*
	* @return array<string, array> Array of provider configurations, keyed by provider ID.
	*/
	public function getEnabledProviders(): array
	{
		$providers = $this->get('providers', []);
		$enabled = [];

		foreach ($providers as $id => $config) {
			if (isset($config['enabled']) && $config['enabled'] === true) {
				$enabled[$id] = $config;
			}
		}

		return $enabled;
	}

	/**
	* Load configuration from WordPress options.
	*
	* @return void
	*/
	private function loadFromWordPress(): void
	{
		global $wpdb;

		// Bail if $wpdb isn't available (not in WordPress context)
		if (!isset($wpdb) || !is_object($wpdb)) {
			return;
		}

		// Get all plugin options in one query
		$options = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
				self::OPTION_PREFIX . '%'
			)
		);

		if (!is_array($options)) {
			return;
		}

		foreach ($options as $option) {
			// Convert option name to config key
			// wp_social_auth_google_client_id -> providers.google.client_id
			$configKey = $this->optionToConfigKey($option->option_name);
			$value = maybe_unserialize($option->option_value);

			$this->set($configKey, $value);
		}
	}

	/**
	* Load configuration from environment variables.
	*
	* @return void
	*/
	private function loadFromEnvironment(): void
	{
		// Process $_ENV variables
		foreach ($_ENV as $key => $value) {
			if (strpos($key, self::ENV_PREFIX) === 0) {
				$configKey = $this->environmentToConfigKey($key);
				$this->set($configKey, $this->castEnvironmentValue($value));
			}
		}

		// Also check getenv() for variables
		foreach (array_keys($_SERVER) as $key) {
			if (strpos($key, self::ENV_PREFIX) === 0 && ($value = getenv($key)) !== false) {
				$configKey = $this->environmentToConfigKey($key);
				$this->set($configKey, $this->castEnvironmentValue($value));
			}
		}
	}

	/**
	* Cast environment variable to appropriate type.
	*
	* @param string $value Environment variable value.
	* @return mixed Properly typed value.
	*/
	private function castEnvironmentValue(string $value)
	{
		// Convert "true" and "false" strings to booleans
		if (strtolower($value) === 'true') {
			return true;
		}

		if (strtolower($value) === 'false') {
			return false;
		}

		// Convert numeric strings to numbers
		if (is_numeric($value)) {
			return strpos($value, '.') !== false ? (float) $value : (int) $value;
		}

		// Return original string value
		return $value;
	}

	/**
	* Convert environment variable name to configuration key.
	*
	* @param string $envVar Environment variable name.
	* @return string Configuration key.
	*/
	private function environmentToConfigKey(string $envVar): string
	{
		// Remove prefix
		$key = substr($envVar, strlen(self::ENV_PREFIX));

		// Convert to lowercase
		$key = strtolower($key);

		// Replace underscores with dots for nested keys
		$parts = explode('_', $key);

		// Handle special naming conventions for providers
		if (count($parts) >= 3 && in_array($parts[0], ['GOOGLE', 'FACEBOOK'], true)) {
			// GOOGLE_CLIENT_ID -> providers.google.client_id
			$provider = strtolower($parts[0]);
			array_shift($parts);
			return 'providers.' . $provider . '.' . implode('.', array_map('strtolower', $parts));
		}

		// General case
		return implode('.', array_map('strtolower', $parts));
	}

	/**
	* Convert WordPress option name to configuration key.
	*
	* @param string $option Option name.
	* @return string Configuration key.
	*/
	private function optionToConfigKey(string $option): string
	{
		// Remove prefix
		$key = substr($option, strlen(self::OPTION_PREFIX));

		// Handle specific option naming patterns
		if (preg_match('/^(google|facebook)_(.+)$/', $key, $matches)) {
			// google_client_id -> providers.google.client_id
			return 'providers.' . $matches[1] . '.' . str_replace('_', '.', $matches[2]);
		}

		// General case
		return str_replace('_', '.', $key);
	}

	/**
	* Get a nested array value using an array of keys.
	*
	* @param array $array Array to search in.
	* @param array $keys Keys to traverse.
	* @return mixed|null Found value or null if not found.
	*/
	private function getNestedValue(array $array, array $keys)
	{
		$current = $array;

		foreach ($keys as $key) {
			if (!is_array($current) || !array_key_exists($key, $current)) {
				return null;
			}
			$current = $current[$key];
		}

		return $current;
	}

	/**
	* Set a nested array value using an array of keys.
	*
	* @param array $array Array to modify by reference.
	* @param array $keys Keys to traverse.
	* @param mixed $value Value to set.
	* @return void
	*/
	private function setNestedValue(array &$array, array $keys, $value): void
	{
		$current = &$array;

		foreach ($keys as $key) {
			if (!is_array($current)) {
				$current = [];
			}

			if (!array_key_exists($key, $current) || !is_array($current[$key])) {
				$current[$key] = [];
			}

			$current = &$current[$key];
		}

		$current = $value;
	}

	/**
	* Save configuration to WordPress options.
	*
	* @param bool $onlyChanged Save only changed values. 
	* @return bool True if all options were saved successfully.
	*/
	public function save(bool $onlyChanged = true): bool
	{
		// Bail if not in WordPress context
		if (!function_exists('update_option')) {
			return false;
		}

		$flatConfig = $this->flattenConfig();
		$success = true;

		foreach ($flatConfig as $key => $value) {
			$optionName = self::OPTION_PREFIX . $key;

			// Skip if only saving changed values and value hasn't changed
			if ($onlyChanged && get_option($optionName) === $value) {
				continue;
			}

			if (!update_option($optionName, $value)) {
				$success = false;
			}
		}

		return $success;
	}

	/**
	* Flatten configuration for saving to WordPress options.
	*
	* @return array Flattened configuration with underscores.
	*/
	private function flattenConfig(): array
	{
		$result = [];
		$flat = $this->flattenArray($this->config);

		foreach ($flat as $key => $value) {
			// Handle provider configurations specially
			if (strpos($key, 'providers.') === 0) {
				$parts = explode('.', $key);
				if (count($parts) >= 3) {
					// providers.google.client_id -> google_client_id
					$provider = $parts[1];
					array_shift($parts); // remove 'providers'
					array_shift($parts); // remove provider name
					$result[$provider . '_' . implode('_', $parts)] = $value;
					continue;
				}
			}

			// General case
			$result[str_replace('.', '_', $key)] = $value;
		}

		return $result;
	}

	/**
	* Flatten a multi-dimensional array with dot notation.
	*
	* @param array $array Array to flatten.
	* @param string $prefix Key prefix.
	* @return array Flattened array.
	*/
	private function flattenArray(array $array, string $prefix = ''): array
	{
		$result = [];

		foreach ($array as $key => $value) {
			$newKey = $prefix ? $prefix . '.' . $key : $key;

			if (is_array($value) && !empty($value)) {
				$result = array_merge($result, $this->flattenArray($value, $newKey));
			} else {
				$result[$newKey] = $value;
			}
		}

		return $result;
	}

	/**
	* Get all configuration as an array.
	*
	* @return array Complete configuration array.
	*/
	public function toArray(): array
	{
		return $this->config;
	}
}

