<?php
/**
 * Abstract Provider
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */



namespace WP_Social_Auth;

use Psr\Log\LoggerInterface;
use WP_Social_Auth\Exception\WP_Social_Auth_Config_Exception;
use WP_Social_Auth\Exception\WP_Social_Auth_Provider_Exception;

/**
* Base class for social authentication providers.
*/
abstract class WP_Social_Auth_Abstract_Provider implements ProviderInterface
{
	/**
	* Provider configuration.
	*
	* @var array
	*/
	protected array $config;

	/**
	* Logger instance.
	*
	* @var LoggerInterface
	*/
	protected LoggerInterface $logger;

	/**
	* Redirect URI for OAuth callback.
	*
	* @var string
	*/
	protected string $redirectUri;

	/**
	* State parameter key prefix for transients.
	*
	* @var string
	*/
	protected const STATE_TRANSIENT_PREFIX = 'wp_social_auth_state_';

	/**
	* Constructor.
	*
	* @param array $config Provider configuration.
	* @param LoggerInterface $logger PSR-3 logger instance.
	*/
	public function __construct(array $config, LoggerInterface $WP_Social_Auth_Logger
	{
		$this->config = $config;
		$this->logger = $logger;
		$this->redirectUri = admin_url('admin-ajax.php?action=social_login_callback');
	}

	/**
	* Validate the provider configuration.
	*
	* @return bool True if the configuration is valid.
	* @throws ConfigException If any required parameter is missing.
	*/
	public function validateConfig(): bool
	{
		$requiredConfig = $this->getRequiredConfigKeys();
		return $this->validateRequiredConfig($requiredConfig);
	}

	/**
	* Check if the provider has valid credentials.
	* 
	* @return bool True if the provider is configured with valid credentials.
	*/
	public function isConfigured(): bool
	{
		try {
			return $this->validateConfig();
		} catch (WP_Social_Auth_Config_Exceptione) {
			return false;
		}
	}

	/**
	* Get required configuration keys for this provider.
	*
	* @return array Array of required configuration keys.
	*/
	abstract protected function getRequiredConfigKeys(): array;

	/**
	* Generate a secure state parameter for OAuth requests.
	*
	* @return string The generated state parameter.
	*/
	protected function generateState(): string
	{
		$state = wp_generate_password(32, false);
		$transientKey = self::STATE_TRANSIENT_PREFIX . md5($state);
		set_transient($transientKey, time(), 5 * MINUTE_IN_SECONDS);
		return $state;
	}

	/**
	* Verify the state parameter returned from the OAuth provider.
	*
	* @param string $state The state parameter to verify.
	* @return bool True if the state is valid.
	*/
	protected function verifyState(string $state): bool
	{
		$transientKey = self::STATE_TRANSIENT_PREFIX . md5($state);
		$stateTime = get_transient($transientKey);

		if ($stateTime === false) {
			$this->logger->warning('Invalid state parameter', [
				'provider' => $this->getIdentifier(),
				'state' => substr($state, 0, 8) . '...',
			]);
			return false;
		}

		delete_transient($transientKey);

		// Check if state is older than 5 minutes
		if ((time() - $stateTime) > (5 * MINUTE_IN_SECONDS)) {
			$this->logger->warning('Expired state parameter', [
				'provider' => $this->getIdentifier(),
				'state' => substr($state, 0, 8) . '...',
				'age' => time() - $stateTime,
			]);
			return false;
		}

		return true;
	}

	/**
	* Make an HTTP request with proper error handling.
	*
	* @param string $url The URL to request.
	* @param array $args WordPress HTTP API arguments.
	* @return array The response data as an associative array.
	* @throws ProviderException If the request fails.
	*/
	protected function makeRequest(string $url, array $args = []): array
	{
		$response = wp_remote_request($url, $args);

		if (is_wp_error($response)) {
			$this->logger->error('Provider request failed', [
				'provider' => $this->getIdentifier(),
				'url' => $url,
				'error' => $response->get_error_message(),
			]);
			throw new WP_Social_Auth_Provider_Exception
				'Failed to communicate with provider: ' . $response->get_error_message(),
				'Unable to connect to authentication service. Please try again later.'
			);
		}

		$status = wp_remote_retrieve_response_code($response);
		if ($status < 200 || $status >= 300) {
			$this->logger->error('Provider returned error status', [
				'provider' => $this->getIdentifier(),
				'url' => $url,
				'status' => $status,
				'body' => wp_remote_retrieve_body($response),
			]);
			throw new WP_Social_Auth_Provider_Exception
				"Provider returned error status: {$status}",
				'Authentication service returned an error. Please try again later.'
			);
		}

		$body = wp_remote_retrieve_body($response);
		$data = json_decode($body, true);

		if (JSON_ERROR_NONE !== json_last_error()) {
			$this->logger->error('Invalid JSON response from provider', [
				'provider' => $this->getIdentifier(),
				'url' => $url,
				'json_error' => json_last_error_msg(),
				'response_body' => substr($body, 0, 1000),  // Log first 1000 chars only
			]);
			throw new WP_Social_Auth_Provider_Exception
				'Invalid response from provider: ' . json_last_error_msg(),
				'Received invalid response from authentication service. Please try again.'
			);
		}

		return $data;
	}

	/**
	* Validate required configuration parameters.
	*
	* @param array $required Array of required configuration keys.
	* @return bool True if all required parameters are present.
	* @throws ConfigException If any required parameter is missing.
	*/
	protected function validateRequiredConfig(array $required): bool
	{
		$missing = [];

		foreach ($required as $key) {
			if (empty($this->config[$key])) {
				$missing[] = $key;
			}
		}

		if (!empty($missing)) {
			throw new WP_Social_Auth_Config_Exception
				sprintf(
					'Missing required configuration parameters for %s provider: %s',
					$this->getIdentifier(),
					implode(', ', $missing)
				)
			);
		}

		return true;
	}
}

