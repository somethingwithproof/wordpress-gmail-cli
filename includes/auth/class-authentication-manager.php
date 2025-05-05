<?php
/**
 * Authentication Manager
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */

namespace WP_Social_Auth\Auth;

use Psr\Log\LoggerInterface;
use WP_Social_Auth\Configuration\Configuration;
use WP_Social_Auth\Exception\AuthException;
use WP_Social_Auth\Exception\RateLimitException;
use WP_Social_Auth\Providers\ProviderFactory;
use WP_Social_Auth\User\UserManager;

class Authentication_Manager {
    /** @var ProviderFactory */
    private ProviderFactory $provider_factory;

    /** @var UserManager */
    private UserManager $user_manager;

    /** @var Configuration */
    private Configuration $config;

    /** @var LoggerInterface */
    private LoggerInterface $logger;

    /**
     * Constructor.
     *
     * @param ProviderFactory   $provider_factory Provider factory instance.
     * @param UserManager      $user_manager     User manager instance.
     * @param Configuration    $config           Configuration instance.
     * @param LoggerInterface  $logger           Logger instance.
     */
    public function __construct(
        ProviderFactory $provider_factory,
        UserManager $user_manager,
        Configuration $config,
        LoggerInterface $logger
    ) {
        $this->provider_factory = $provider_factory;
        $this->user_manager = $user_manager;
        $this->config = $config;
        $this->logger = $logger;
    }

    /**
     * Handle authentication callback.
     *
     * @throws AuthException If authentication fails.
     * @throws RateLimitException If rate limit is exceeded.
     */
    public function handle_callback(): void {
        try {
            // Verify nonce
            $nonce = isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '';
            $provider_id = isset($_REQUEST['provider']) ? sanitize_text_field(wp_unslash($_REQUEST['provider'])) : '';
            
            if (!wp_verify_nonce($nonce, 'social-auth-' . $provider_id)) {
                throw new AuthException(
                    'Invalid nonce',
                    __('Authentication failed. Please try again.', 'wp-social-auth')
                );
            }

            // Check rate limiting
            if (!$this->check_rate_limit()) {
                throw new RateLimitException();
            }

            // Get provider
            $provider = $this->provider_factory->create_provider($provider_id);

            // Get authorization code
            $code = isset($_GET['code']) ? sanitize_text_field(wp_unslash($_GET['code'])) : '';
            if (empty($code)) {
                throw new AuthException(
                    'Missing authorization code',
                    __('Authentication failed. Please try again.', 'wp-social-auth')
                );
            }

            // Get user data from provider
            $user_data = $provider->get_user_data($code);

            // Create or update user
            $user = $this->user_manager->create_or_update_user($user_data);

            // Log the user in
            $this->login_user($user);

            // Get redirect URL
            $redirect_to = isset($_REQUEST['redirect_to']) 
                ? esc_url_raw(wp_unslash($_REQUEST['redirect_to'])) 
                : admin_url();

            // Redirect
            wp_safe_redirect($redirect_to);
            exit;

        } catch (AuthException $e) {
            $this->logger->error('Authentication error', [
                'error' => $e->getMessage(),
                'provider' => $provider_id ?? 'unknown',
            ]);

            wp_safe_redirect(
                add_query_arg(
                    [
                        'login' => 'failed',
                        'reason' => 'auth_error',
                        'message' => urlencode($e->getUserMessage()),
                    ],
                    wp_login_url()
                )
            );
            exit;
        }
    }

    /**
     * Check rate limiting.
     *
     * @return bool True if within rate limit.
     */
    private function check_rate_limit(): bool {
        if (!$this->config->get('security.rate_limit.enabled', true)) {
            return true;
        }

        $ip = $this->get_client_ip();
        $key = 'wp_social_auth_rate_limit_' . md5($ip);
        $attempts = get_transient($key);

        if (false === $attempts) {
            set_transient(
                $key,
                1,
                $this->config->get('security.rate_limit.window', 300)
            );
            return true;
        }

        if ($attempts >= $this->config->get('security.rate_limit.max_attempts', 5)) {
            return false;
        }

        set_transient(
            $key,
            $attempts + 1,
            $this->config->get('security.rate_limit.window', 300)
        );

        return true;
    }

    /**
     * Get client IP address.
     *
     * @return string IP address.
     */
    private function get_client_ip(): string {
        $ip = '';
        
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_CLIENT_IP']));
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']));
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        return $ip;
    }

    /**
     * Log user in.
     *
     * @param \WP_User $user User to log in.
     */
    private function login_user(\WP_User $user): void {
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        
        do_action('wp_login', $user->user_login, $user);
        
        $this->logger->info('User logged in successfully', [
            'user_id' => $user->ID,
            'email' => $user->user_email,
        ]);
    }
}
