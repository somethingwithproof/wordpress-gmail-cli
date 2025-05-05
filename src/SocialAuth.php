<?php

namespace WordPressGmailCli\SocialAuth;

/**
 * Main class for handling social authentication.
 */
class SocialAuth
{
    private string $googleClientId;
    private string $googleClientSecret;
    private string $facebookAppId;
    private string $facebookAppSecret;
    private string $redirectUri;

    /**
     * Constructor.
     *
     * @param array $config Configuration array containing API keys/secrets.
     */
    public function __construct(array $config)
    {
        $this->googleClientId     = $config['google_client_id'] ?? '';
        $this->googleClientSecret = $config['google_client_secret'] ?? '';
        $this->facebookAppId      = $config['facebook_app_id'] ?? '';
        $this->facebookAppSecret  = $config['facebook_app_secret'] ?? '';
        $this->redirectUri        = admin_url('admin-ajax.php?action=social_login_callback');

        // Initialize hooks.
        add_action('login_form', [$this, 'addSocialLoginButtons']);
        add_action('wp_ajax_nopriv_social_login_callback', [$this, 'handleSocialLoginCallback']);
        add_action('wp_ajax_social_login_callback', [$this, 'handleSocialLoginCallback']);
        add_action('wp_enqueue_scripts', [$this, 'enqueueScripts']);
        add_action('login_enqueue_scripts', [$this, 'enqueueScripts']);
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('admin_menu', [$this, 'addSettingsPage']);
    }

    /**
     * Add social login buttons to the WordPress login form.
     *
     * @return void
     */
    public function addSocialLoginButtons(): void
    {
        ?>
        <div class="social-login-buttons" style="margin-bottom: 20px; text-align: center;">
            <?php if ($this->googleClientId) : ?>
            <a href="<?php echo esc_url($this->getGoogleAuthUrl()); ?>" class="button" 
               style="background: #4285F4; color: white; margin-right: 10px; text-decoration: none; 
                      padding: 8px 12px; border-radius: 4px;">
                <span style="font-size: 16px; vertical-align: middle;">G</span> Login with Google
            </a>
            <?php endif; ?>

            <?php if ($this->facebookAppId) : ?>
            <a href="<?php echo esc_url($this->getFacebookAuthUrl()); ?>" class="button" 
               style="background: #3b5998; color: white; text-decoration: none; padding: 8px 12px; 
                      border-radius: 4px;">
                <span style="font-size: 16px; vertical-align: middle;">f</span> Login with Facebook
            </a>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Handle the social login callback. Verifies state, gets user data, and logs in/creates user.
     *
     * @return void
     */
    public function handleSocialLoginCallback(): void
    {
        // Verify nonce for security.
        $provider = isset($_GET['provider']) ? sanitize_text_field(wp_unslash($_GET['provider'])) : '';
        $code     = isset($_GET['code']) ? sanitize_text_field(wp_unslash($_GET['code'])) : '';
        $state    = isset($_GET['state']) ? sanitize_text_field(wp_unslash($_GET['state'])) : '';

        // Validate provider.
        if (!in_array($provider, ['google', 'facebook'], true)) {
            wp_safe_redirect(wp_login_url());
            exit;
        }

        // Verify state parameter to prevent CSRF.
        $nonceAction = $provider === 'google' ? 'google_login' : 'facebook_login';
        if (!wp_verify_nonce($state, $nonceAction)) {
            wp_safe_redirect(wp_login_url() . '?login=failed&reason=invalid_state');
            exit;
        }

        if (empty($code)) {
            wp_safe_redirect(wp_login_url());
            exit;
        }

        try {
            $userData = null;

            if ($provider === 'google') {
                $userData = $this->getGoogleUserData($code);
            } elseif ($provider === 'facebook') {
                $userData = $this->getFacebookUserData($code);
            }

            if ($userData && isset($userData['email']) && is_email($userData['email'])) {
                $this->loginOrCreateUser($userData);
            } else {
                // Redirect if email is not valid or not provided.
                wp_safe_redirect(wp_login_url() . '?login=failed&reason=email_error');
                exit;
            }
        } catch (\Exception $e) {
            // Don't expose detailed error messages to users.
            error_log('Social login error: ' . $e->getMessage());
            wp_safe_redirect(wp_login_url() . '?login=failed&reason=provider_error');
            exit;
        }
    }

    /**
     * Get Google authentication URL.
     *
     * @return string Google Auth URL.
     */
    private function getGoogleAuthUrl(): string
    {
        $params = [
            'client_id'     => $this->googleClientId,
            'redirect_uri'  => $this->redirectUri . '&provider=google',
            'response_type' => 'code',
            'scope'         => 'email profile',
            'access_type'   => 'online',
            'state'         => wp_create_nonce('google_login'), // CSRF protection.
        ];

        return 'https://accounts.google.com/o/oauth2/auth?' . http_build_query($params);
    }

    /**
     * Get Facebook authentication URL.
     *
     * @return string Facebook Auth URL.
     */
    private function getFacebookAuthUrl(): string
    {
        $params = [
            'client_id'     => $this->facebookAppId,
            'redirect_uri'  => $this->redirectUri . '&provider=facebook',
            'response_type' => 'code',
            'scope'         => 'email', // Request email permission.
            'state'         => wp_create_nonce('facebook_login'), // CSRF protection.
        ];

        // Ensure correct Facebook API version (check documentation for current).
        return 'https://www.facebook.com/v18.0/dialog/oauth?' . http_build_query($params);
    }

    /**
     * Get Google user data after exchanging the code for a token.
     *
     * @param string $code Authorization code from Google.
     * @throws \Exception If token or user info retrieval fails.
     * @return array User data array.
     */
    private function getGoogleUserData(string $code): array
    {
        // Exchange code for access token.
        $tokenUrl = 'https://oauth2.googleapis.com/token';
        $tokenParams = [
            'client_id'     => $this->googleClientId,
            'client_secret' => $this->googleClientSecret,
            'code'          => $code,
            'redirect_uri'  => $this->redirectUri . '&provider=google',
            'grant_type'    => 'authorization_code',
        ];

        $response = wp_remote_post(
            $tokenUrl,
            [
                'body'    => $tokenParams,
                'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
            ]
        );

        if (is_wp_error($response)) {
            throw new \Exception('Failed to get Google access token: ' . $response->get_error_message());
        }

        $tokenData = json_decode(wp_remote_retrieve_body($response), true);

        if (!isset($tokenData['access_token'])) {
            $errorDescription = $tokenData['error_description'] ?? 'Unknown error';
            throw new \Exception('Failed to get Google access token: ' . $errorDescription);
        }

        // Get user info.
        $userInfoUrl = 'https://www.googleapis.com/oauth2/v3/userinfo';
        $userInfoResponse = wp_remote_get(
            $userInfoUrl,
            [
                'headers' => ['Authorization' => 'Bearer ' . $tokenData['access_token']],
            ]
        );

        if (is_wp_error($userInfoResponse)) {
            throw new \Exception('Failed to get Google user info: ' . $userInfoResponse->get_error_message());
        }

        $userInfo = json_decode(wp_remote_retrieve_body($userInfoResponse), true);

        return [
            'email'        => $userInfo['email'] ?? '',
            'first_name'   => $userInfo['given_name'] ?? '',
            'last_name'    => $userInfo['family_name'] ?? '',
            'display_name' => $userInfo['name'] ?? '',
            'provider'     => 'google',
            'provider_id'  => $userInfo['sub'] ?? '', // 'sub' is the standard Google user ID.
        ];
    }

    /**
     * Get Facebook user data after exchanging the code for a token.
     *
     * @param string $code Authorization code from Facebook.
     * @throws \Exception If token or user info retrieval fails.
     * @return array User data array.
     */
    private function getFacebookUserData(string $code): array
    {
        // Exchange code for access token.
        // Ensure correct Facebook API version (check documentation for current).
        $tokenUrl = 'https://graph.facebook.com/v18.0/oauth/access_token';
        $tokenParams = [
            'client_id'     => $this->facebookAppId,
            'client_secret' => $this->facebookAppSecret,
            'code'          => $code,
            'redirect_uri'  => $this->redirectUri . '&provider=facebook',
        ];

        $response = wp_remote_get($tokenUrl . '?' . http_build_query($tokenParams));

        if (is_wp_error($response)) {
            throw new \Exception('Failed to get Facebook access token: ' . $response->get_error_message());
        }

        $tokenData = json_decode(wp_remote_retrieve_body($response), true);

        if (!isset($tokenData['access_token'])) {
            $errorMessage = $tokenData['error']['message'] ?? 'Unknown error';
            throw new \Exception('Failed to get Facebook access token: ' . $errorMessage);
        }

        // Get user info.
        // Ensure correct Facebook API version (check documentation for current).
        $userInfoUrl = 'https://graph.facebook.com/v18.0/me';
        $userInfoParams = [
            'fields'       => 'id,email,first_name,last_name,name', // Specify required fields.
            'access_token' => $tokenData['access_token'],
        ];

        $userInfoResponse = wp_remote_get($userInfoUrl . '?' . http_build_query($userInfoParams));

        if (is_wp_error($userInfoResponse)) {
            throw new \Exception('Failed to get Facebook user info: ' . $userInfoResponse->get_error_message());
        }

        $userInfo = json_decode(wp_remote_retrieve_body($userInfoResponse), true);

        return [
            'email'        => $userInfo['email'] ?? '', // Email might not be returned if user denies permission.
            'first_name'   => $userInfo['first_name'] ?? '',
            'last_name'    => $userInfo['last_name'] ?? '',
            'display_name' => $userInfo['name'] ?? '',
            'provider'     => 'facebook',
            'provider_id'  => $userInfo['id'] ?? '',
        ];
    }

    /**
     * Login or create a user based on social login data.
     *
     * @param array $userData User data from the provider.
     * @throws \Exception If user creation fails.
     * @return void
     */
    private function loginOrCreateUser(array $userData): void
    {
        $user = get_user_by('email', $userData['email']);

        if (!$user) {
            // Create a new user.
            $username = $this->generateUniqueUsername($userData['email']);

            $userId = wp_create_user($username, wp_generate_password(), $userData['email']);

            if (is_wp_error($userId)) {
                throw new \Exception('Failed to create user: ' . $userId->get_error_message());
            }

            // Update user meta with details from social profile.
            wp_update_user(
                [
                    'ID'           => $userId,
                    'first_name'   => $userData['first_name'],
                    'last_name'    => $userData['last_name'],
                    'display_name' => $userData['display_name'],
                ]
            );

            update_user_meta($userId, 'social_login_provider', $userData['provider']);
            update_user_meta($userId, 'social_login_provider_id', $userData['provider_id']);

            $user = get_user_by('id', $userId);

            // Optionally, send the new user notification.
            // wp_new_user_notification($userId, null, 'user'); // or 'both'
        } else {
            // Optional: Update existing user's meta if needed (e.g., refresh provider ID).
            update_user_meta($user->ID, 'social_login_provider', $userData['provider']);
            update_user_meta($user->ID, 'social_login_provider_id', $userData['provider_id']);
        }

        // Log the user in.
        wp_set_current_user($user->ID); // Ensure the user context is set before setting the cookie.
        wp_set_auth_cookie($user->ID, true);

        // Redirect to admin dashboard or home page based on capabilities.
        $redirectUrl = user_can($user->ID, 'manage_options') ? admin_url() : home_url();
        wp_safe_redirect($redirectUrl);
        exit;
    }

    /**
     * Generate a unique username based on email prefix.
     * Appends numbers if the username already exists.
     *
     * @param string $email User's email address.
     * @return string A unique username.
     */
    private function generateUniqueUsername(string $email): string
    {
        $emailParts = explode('@', $email);
        $username = sanitize_user(current($emailParts), true);
        
        // Ensure username is not empty after sanitization.
        if (empty($username)) {
            $username = 'user' . time(); // Fallback username.
        }
        
        $originalUsername = $username;
        $i = 1;

        while (username_exists($username)) {
            $username = $originalUsername . $i;
            $i++;
        }

        return $username;
    }

    /**
     * Enqueue scripts and styles. (Currently only Dashicons).
     *
     * @return void
     */
    public function enqueueScripts(): void
    {
        // Enqueue Dashicons for potential use in buttons or UI elements.
        wp_enqueue_style('dashicons');
    }

    /**
     * Register plugin settings.
     *
     * @return void
     */
    public function registerSettings(): void
    {
        register_setting(
            'wp_social_auth_settings',
            'wp_social_auth_google_client_id',
            ['sanitize_callback' => 'sanitize_text_field']
        );
        register_setting(
            'wp_social_auth_settings',
            'wp_social_auth_google_client_secret',
            ['sanitize_callback' => 'sanitize_text_field']
        );
        register_setting(
            'wp_social_auth_settings',
            'wp_social_auth_facebook_app_id',
            ['sanitize_callback' => 'sanitize_text_field']
        );
        register_setting(
            'wp_social_auth_settings',
            'wp_social_auth_facebook_app_secret',
            ['sanitize_callback' => 'sanitize_text_field']
        );
    }

    /**
     * Add settings page to the WordPress admin menu.
     *
     * @return void
     */
    public function addSettingsPage(): void
    {
        add_options_page(
            'Social Login Settings', // Page title.
            'Social Login', // Menu title.
            'manage_options', // Capability required.
            'wp-social-auth-settings', // Menu slug.
            [$this, 'renderSettingsPage'] // Function to display the page content.
        );
    }

    /**
     * Render the settings page HTML.
     *
     * @return void
     */
    public function renderSettingsPage(): void
    {
        // Check user capabilities.
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <form method="post" action="options.php">
                <?php settings_fields('wp_social_auth_settings'); ?>
                <?php // Sections can be added here using add_settings_section() and do_settings_sections() ?>

                <h2>Google Authentication</h2>
                <p>
                    Register your application at 
                    <a href="https://console.developers.google.com/" target="_blank" rel="noopener noreferrer">
                        Google Cloud Console
                    </a> 
                    to get these credentials.
                </p>
                <p>
                    Your authorized redirect URI is: 
                    <code><?php echo esc_html($this->redirectUri . '&provider=google'); ?></code>
                </p>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="wp_social_auth_google_client_id">Client ID</label></th>
                        <td>
                            <input type="text" 
                                id="wp_social_auth_google_client_id" 
                                name="wp_social_auth_google_client_id" 
                                value="<?php echo esc_attr(get_option('wp_social_auth_google_client_id')); ?>" 
                                class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="wp_social_auth_google_client_secret">Client Secret</label></th>
                        <td>
                            <input type="password" 
                                id="wp_social_auth_google_client_secret" 
                                name="wp_social_auth_google_client_secret" 
                                value="<?php echo esc_attr(get_option('wp_social_auth_google_client_secret')); ?>" 
                                class="regular-text" />
                        </td>
                    </tr>
                </table>

                <h2>Facebook Authentication</h2>
                <p>
                    Register your application at 
                    <a href="https://developers.facebook.com/apps/" target="_blank" rel="noopener noreferrer">
                        Facebook for Developers
                    </a> 
                    to get these credentials.
                </p>
                <p>
                    Your valid OAuth redirect URI is: 
                    <code><?php echo esc_html($this->redirectUri . '&provider=facebook'); ?></code>
                </p>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="wp_social_auth_facebook_app_id">App ID</label></th>
                        <td>
                            <input type="text" 
                                id="wp_social_auth_facebook_app_id" 
                                name="wp_social_auth_facebook_app_id" 
                                value="<?php echo esc_attr(get_option('wp_social_auth_facebook_app_id')); ?>" 
                                class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="wp_social_auth_facebook_app_secret">App Secret</label></th>
                        <td>
                            <input type="password" 
                                id="wp_social_auth_facebook_app_secret" 
                                name="wp_social_auth_facebook_app_secret" 
                                value="<?php echo esc_attr(get_option('wp_social_auth_facebook_app_secret')); ?>" 
                                class="regular-text" />
                        </td>
                    </tr>
                </table>

                <?php submit_button('Save Settings'); ?>
            </form>
        </div>
        <?php
    }
}