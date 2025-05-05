<?php
/**
 * Provider Factory
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */



namespace WP_Social_Auth;

use Psr\Log\LoggerInterface;
use WP_Social_Auth\Exception\WP_Social_Auth_Config_Exception;

/**
* Factory class for creating and managing social authentication providers.
*/
class WP_Social_Auth_Provider_Factory
{
	/**
	* Registered provider classes.
	*
	* @var array<string, class-string<ProviderInterface>>
	*/
	private array $providers = [];

	/**
	* PSR-3 logger instance.
	*
	* @var LoggerInterface
	*/
	private LoggerInterface $logger;

	/**
	* Constructor.
	*
	* @param LoggerInterface $logger PSR-3 logger instance.
	*/
	public function __construct(LoggerInterface $WP_Social_Auth_Logger
	{
		$this->logger = $logger;
		$this->registerDefaultProviders();
	}

	/**
	* Register default social authentication providers.
	*
	* @return void
	*/
	protected function registerDefaultProviders(): void
	{
		$this->registerProvider('google', WP_Social_Auth_Google_Providerclass);
		// Register other providers as they are implemented
		// $this->registerProvider('facebook', FacebookProvider::class);

		/**
		* Action hook to register additional providers.
		*
		* @param WP_Social_Auth_Provider_Factoryfactory The provider factory instance.
		*/
		do_action('wp_social_auth_register_providers', $this);
	}

	/**
	* Register a new provider.
	*
	* @param string $identifier Provider identifier.
	* @param class-string<ProviderInterface> $providerClass Provider class name.
	* @return self
	* @throws \InvalidArgumentException If provider class doesn't implement ProviderInterface.
	*/
	public function registerProvider(string $identifier, string $providerClass): self
	{
		if (!is_subclass_of($providerClass, WP_Social_Auth_Providerclass)) {
			throw new \InvalidArgumentException(
				sprintf(
					'Provider class %s must implement %s',
					$providerClass,
					WP_Social_Auth_Providerclass
				)
			);
		}

		$this->providers[$identifier] = $providerClass;

		$this->logger->debug('Registered provider', [
			'provider' => $identifier,
			'class' => $providerClass,
		]);

		return $this;
	}

	/**
	* Create a provider instance.
	*
	* @param string $identifier Provider identifier.
	* @param array|null $config Optional provider configuration override.
	* @return ProviderInterface
	* @throws ConfigException If provider is not registered or configuration is invalid.
	*/
	public function createProvider(string $identifier, ?array $config = null): ProviderInterface
	{
		if (!$this->hasProvider($identifier)) {
			throw new WP_Social_Auth_Config_Exception
				sprintf('Provider "%s" is not registered', $identifier)
			);
		}

		$providerClass = $this->providers[$identifier];
		$providerConfig = $config ?? $this->loadProviderConfig($identifier);

		try {
			$provider = new $providerClass($providerConfig, $this->WP_Social_Auth_Logger;
			$provider->validateConfig();

			return $provider;
		} catch (WP_Social_Auth_Config_Exceptione) {
			$this->logger->error('Provider configuration error', [
				'provider' => $identifier,
				'error' => $e->getMessage(),
			]);
			throw $e;
		}
	}

	/**
	* Get all registered and properly configured providers.
	*
	* @return array<string, ProviderInterface> Array of provider instances indexed by identifier.
	*/
	public function getConfiguredProviders(): array
	{
		$configuredProviders = [];

		foreach (array_keys($this->providers) as $identifier) {
			try {
				$provider = $this->createProvider($identifier);
				if ($provider->isConfigured()) {
					$configuredProviders[$identifier] = $provider;
				}
			} catch (WP_Social_Auth_Config_Exceptione) {
				// Skip providers with invalid WP_Social_Auth_Configurationthis->logger->debug('Skipping unconfigured provider', [
					'provider' => $identifier,
					'reason' => $e->getMessage(),
				]);
				continue;
			}
		}

		return $configuredProviders;
	}

	/**
	* Load provider configuration from WordPress options.
	*
	* @param string $identifier Provider identifier.
	* @return array Provider configuration.
	*/
	protected function loadProviderConfig(string $identifier): array
	{
		$config = [];

		switch ($identifier) {
			case 'google':
				$config = [
					'client_id' => $this->getOption('wp_social_auth_google_client_id'),
					'client_secret' => $this->getOption('wp_social_auth_google_client_secret'),
					'hosted_domain' => $this->getOption('wp_social_auth_google_hosted_domain'),
				];
				break;

			case 'facebook':
				$config = [
					'client_id' => $this->getOption('wp_social_auth_facebook_app_id'),
					'client_secret' => $this->getOption('wp_social_auth_facebook_app_secret'),
				];
				break;

			default:
				// Allow custom provider configuration through filter
				break;
		}

		/**
		* Filter provider configuration before instantiation.
		*
		* @param array $config Provider configuration.
		* @param string $identifier Provider identifier.
		*/
		return apply_filters("wp_social_auth_{$identifier}_config", $config);
	}

	/**
	* Get a WordPress option with environment variable fallback.
	*
	* @param string $option Option name.
	* @return string Option value.
	*/
	protected function getOption(string $option): string
	{
		// Convert option name to potential environment variable format
		// wp_social_auth_google_client_id -> WP_SOCIAL_AUTH_GOOGLE_CLIENT_ID
		$envVar = strtoupper(str_replace(['wp_', '_'], ['WP_', '_'], $option));

		// Check environment variable first (useful for Docker/non-DB configs)
		$value = getenv($envVar);

		// Fall back to WordPress option if not found in environment
		if ($value === false) {
			$value = get_option($option, '');
		}

		return $value;
	}

	/**
	* Check if a provider is registered.
	*
	* @param string $identifier Provider identifier.
	* @return bool True if provider is registered.
	*/
	public function hasProvider(string $identifier): bool
	{
		return isset($this->providers[$identifier]);
	}

	/**
	* Get list of registered provider identifiers.
	*
	* @return array List of provider identifiers.
	*/
	public function getRegisteredProviders(): array
	{
		return array_keys($this->providers);
	}
}

