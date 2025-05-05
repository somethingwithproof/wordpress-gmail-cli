<?php
/**
 * Provider Interface
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */



namespace WP_Social_Auth;

/**
* Interface that all social authentication providers must implement.
*/
interface WP_Social_Auth_Provider
{
	/**
	* Get the authentication URL for the provider.
	*
	* @return string The authentication URL.
	*/
	public function getAuthUrl(): string;

	/**
	* Get user data from the provider using the authorization code.
	*
	* @param string $code The authorization code from the provider.
	* @return array The user data array containing at minimum: email, provider_id, and provider
	* @throws \WordPressGmailCli\SocialAuth\Exception\ProviderException
	*/
	public function getUserData(string $code): array;

	/**
	* Validate the provider configuration.
	*
	* @return bool True if the configuration is valid.
	* @throws \WordPressGmailCli\SocialAuth\Exception\ConfigException
	*/
	public function validateConfig(): bool;

	/**
	* Get the provider identifier.
	*
	* @return string The provider identifier (e.g., 'google', 'facebook').
	*/
	public function getIdentifier(): string;

	/**
	* Check if the provider has valid credentials.
	* 
	* @return bool True if the provider is configured with valid credentials.
	*/
	public function isConfigured(): bool;
}

