<?php
/**
 * Google Provider
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */



namespace WP_Social_Auth;

use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Log\LoggerInterface;
use WP_Social_Auth\Exception\WP_Social_Auth_Provider_Exception;

/**
* Google OAuth2 provider implementation.
*/
class WP_Social_Auth_Google_Provider extends AbstractProvider
{
	/**
	* OAuth2 provider instance.
	*
	* @var Google
	*/
	private Google $provider;

	/**
	* Constructor.
	*
	* @param array $config Provider configuration.
	* @param LoggerInterface $logger PSR-3 logger instance.
	*/
	public function __construct(array $config, LoggerInterface $WP_Social_Auth_Logger
	{
		parent::__construct($config, $WP_Social_Auth_Logger;

		$this->provider = new Google([
			'clientId'     => $this->config['client_id'] ?? '',
			'clientSecret' => $this->config['client_secret'] ?? '',
			'redirectUri'  => $this->redirectUri . '&provider=' . $this->getIdentifier(),
			'hostedDomain' => $this->config['hosted_domain'] ?? null, // For Google Workspace accounts only
		]);
	}

	/**
	* {@inheritdoc}
	*/
	public function getIdentifier(): string
	{
		return 'google';
	}

	/**
	* {@inheritdoc}
	*/
	protected function getRequiredConfigKeys(): array
	{
		return ['client_id', 'client_secret'];
	}

	/**
	* {@inheritdoc}
	*/
	public function getAuthUrl(): string
	{
		$options = [
			'scope' => [
				'email',
				'profile',
				'openid',
			],
			'state' => $this->generateState(),
			'access_type' => 'online',
			'prompt' => 'select_account consent',
		];

		// Cache the state in transient for verification
		$transientKey = self::STATE_TRANSIENT_PREFIX . md5($options['state']);
		set_transient($transientKey, time(), 5 * MINUTE_IN_SECONDS);

		return $this->provider->getAuthorizationUrl($options);
	}

	/**
	* {@inheritdoc}
	*/
	public function getUserData(string $code): array
	{
		try {
			// Extract and verify state parameter from $_GET
			$state = isset($_GET['state']) ? sanitize_text_field(wp_unslash($_GET['state'])) : '';

			if (!$state || !$this->verifyState($state)) {
				$this->logger->error('Invalid state parameter', [
					'provider' => $this->getIdentifier(),
					'received_state' => substr($state, 0, 8) . '...',
				]);
				throw new WP_Social_Auth_Provider_Exception
					'Invalid state parameter',
					'Security validation failed. Please try again.'
				);
			}

			// Exchange authorization code for access token
			$token = $this->provider->getAccessToken('authorization_code', [
				'code' => $code
			]);

			// Get user details
			/** @var GoogleUser $user */
			$user = $this->provider->getResourceOwner($token);

			// Verify email is present and verified
			if (empty($user->getEmail())) {
				$this->logger->warning('Google account email missing', [
					'provider' => $this->getIdentifier(),
				]);
				throw new WP_Social_Auth_Provider_Exception
					'Google account email missing',
					'Unable to retrieve email from your Google account. Please ensure your Google account has an email and try again.'
				);
			}

			// Some older accounts may not have the verified email flag
			if (method_exists($user, 'getVerifiedEmail') && !$user->getVerifiedEmail()) {
				$this->logger->warning('Google account email not verified', [
					'provider' => $this->getIdentifier(),
					'email' => $user->getEmail(),
				]);
				throw new WP_Social_Auth_Provider_Exception
					'Google account email not verified',
					'Please verify your Google account email address before continuing.'
				);
			}

			// Build standardized user data array
			$userData = [
				'email' => sanitize_email($user->getEmail()),
				'first_name' => sanitize_text_field($user->getFirstName() ?? ''),
				'last_name' => sanitize_text_field($user->getLastName() ?? ''),
				'display_name' => sanitize_text_field($user->getName() ?? ''),
				'provider' => $this->getIdentifier(),
				'provider_id' => sanitize_text_field($user->getId()),
				'avatar_url' => esc_url_raw($user->getAvatar() ?? ''),
			];

			// Optional data if available
			if (method_exists($user, 'getLocale') && $user->getLocale()) {
				$userData['locale'] = sanitize_text_field($user->getLocale());
			}

			// Store the token in transient for possible future use (profile sync, etc.)
			$tokenData = $token->jsonSerialize();
			$userData['access_token'] = $tokenData['access_token'];

			if (!empty($tokenData['refresh_token'])) {
				$userData['refresh_token'] = $tokenData['refresh_token'];
			}

			if (!empty($tokenData['expires_in'])) {
				$userData['expires_in'] = (int)$tokenData['expires_in'];
				$userData['expires_at'] = time() + $userData['expires_in'];
			}

			$this->logger->info('Google authentication successful', [
				'provider' => $this->getIdentifier(),
				'email' => $userData['email'],
				'provider_id' => $userData['provider_id'],
			]);

			return $userData;
		} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
			$this->logger->error('Google OAuth error', [
				'provider' => $this->getIdentifier(),
				'error' => $e->getMessage(),
				'response' => $e->getResponseBody(),
			]);
			throw new WP_Social_Auth_Provider_Exception
				'Google OAuth error: ' . $e->getMessage(),
				'Unable to authenticate with Google. Please try again later.'
			);
		} catch (WP_Social_Auth_Provider_Exceptione) {
			// Just re-throw our own exceptions
			throw $e;
		} catch (\Exception $e) {
			$this->logger->error('Unexpected error during Google authentication', [
				'provider' => $this->getIdentifier(),
				'error' => $e->getMessage(),
				'trace' => $e->getTraceAsString(),
			]);
			throw new WP_Social_Auth_Provider_Exception
				'Unexpected error during Google authentication: ' . $e->getMessage(),
				'An unexpected error occurred. Please try again later.'
			);
		}
	}
}

