<?php

/**
 * Plugin Name: WordPress Social Authentication
 * Description: Adds Google and Facebook authentication to WordPress login.
 * Version:     1.1.0
 * Author:      WordPress Gmail CLI
 */

// Prevent direct access.
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Main class for handling social authentication.
 */
class WP_Social_Auth
{
    private string $google_client_id;
    private string $google_client_secret;
    private string $facebook_app_id;
    private string $facebook_app_secret;
    private string $redirect_uri;

    /**
     * Constructor.
     *
     * @param array $config Configuration array containing API keys/secrets.
     */
    public function __construct(array $config)
    {
        $this->google_client_id     = $config['google_client_id'] ?? '';
        $this->google_client_secret = $config['google_client_secret'] ?? '';
        $this->facebook_app_id      = $config['facebook_app_id'] ?? '';
        $this->facebook_app_secret  = $config['facebook_app_secret'] ?? '';
        $this->redirect_uri         = admin_url('admin-ajax.php?action=social_login_callback');

        // Initialize hooks.
        add_action('login_form', [$this, 'add_social_login_buttons']);
        add_action('wp_ajax_nopriv_social_login_callback', [$this, 'handle_social_login_callback']);
        add_action('wp_ajax_social_login_callback', [$this, 'handle_social_login_callback']);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('login_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_menu', [$this, 'add_settings_page']);
    }

    /**
     * Add social login buttons to the WordPress login form.
     *
     * @return void
     */
    public function add_social_login_buttons(): void
    {
        ?>
        <div class="social-login-buttons" style="margin-bottom: 20px; text-align: center;">
            <?php if ($this->google_client_id) : ?>
            <a href="<?php echo esc_url($this->get_google_auth_url()); ?>" class="button" style="background: #4285F4; color: white; margin-right: 10px; text-decoration: none; padding: 8px 12px; border-radius: 4px;">
                <span style="font-size: 16px; vertical-align: middle;">G</span> Login with Google
            </a>
            <?php endif; ?>

            <?php if ($this->facebook_app_id) : ?>
            <a href="<?php echo esc_url($this->get_facebook_auth_url()); ?>" class="button" style="background: #3b5998; color: white; text-decoration: none; padding: 8px 12px; border-radius: 4px;">
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
    public function handle_social_login_callback(): void
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
        $nonce_action = $provider === 'google' ? 'google_login' : 'facebook_login';
        if (!wp_verify_nonce($state, $nonce_action)) {
            wp_safe_redirect(wp_login_url() . '?login=failed&reason=invalid_state');
            exit;
        }

        if (empty($code)) {
            wp_safe_redirect(wp_login_url());
            exit;
        }

        try {
            $user_data = null;

            if ($provider === 'google') {
                $user_data = $this->get_google_user_data($code);
            } elseif ($provider === 'facebook') {
                $user_data = $this->get_facebook_user_data($code);
            }

            if ($user_data && isset($user_data['email']) && is_email($user_data['email'])) {
                $this->login_or_create_user($user_data);
            } else {
                // Redirect if email is not valid or not provided.
                wp_safe_redirect(wp_login_url() . '?login=failed&reason=email_error');
                exit;
            }
        } catch (Exception $e) {
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
    private function get_google_auth_url(): string
    {
        $params = [
            'client_id'     => $this->google_client_id,
            'redirect_uri'  => $this->redirect_uri . '&provider=google',
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
    private function get_facebook_auth_url(): string
    {
        $params = [
            'client_id'     => $this->facebook_app_id,
            'redirect_uri'  => $this->redirect_uri . '&provider=facebook',
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
     * @throws Exception If token or user info retrieval fails.
     * @return array User data array.
     */
    private function get_google_user_data(string $code): array
    {
        // Exchange code for access token.
        $token_url    = 'https://oauth2.googleapis.com/token';
        $token_params = [
            'client_id'     => $this->google_client_id,
            'client_secret' => $this->google_client_secret,
            'code'          => $code,
            'redirect_uri'  => $this->redirect_uri . '&provider=google',
            'grant_type'    => 'authorization_code',
        ];

        $response = wp_remote_post(
            $token_url,
            [
                'body'    => $token_params,
                'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
            ]
        );

        if (is_wp_error($response)) {
            throw new Exception('Failed to get Google access token: ' . $response->get_error_message());
        }

        $token_data = json_decode(wp_remote_retrieve_body($response), true);

        if (!isset($token_data['access_token'])) {
            $error_description = $token_data['error_description'] ?? 'Unknown error';
            throw new Exception('Failed to get Google access token: ' . $error_description);
        }

        // Get user info.
        $user_info_url      = 'https://www.googleapis.com/oauth2/v3/userinfo';
        $user_info_response = wp_remote_get(
            $user_info_url,
            [
                'headers' => ['Authorization' => 'Bearer ' . $token_data['access_token']],
            ]
        );

        if (is_wp_error($user_info_response)) {
            throw new Exception('Failed to get Google user info: ' . $user_info_response->get_error_message());
        }

        $user_info = json_decode(wp_remote_retrieve_body($user_info_response), true);

        return [
            'email'        => $user_info['email'] ?? '',
            'first_name'   => $user_info['given_name'] ?? '',
            'last_name'    => $user_info['family_name'] ?? '',
            'display_name' => $user_info['name'] ?? '',
            'provider'     => 'google',
            'provider_id'  => $user_info['sub'] ?? '', // 'sub' is the standard Google user ID.
        ];
    }

    /**
     * Get Facebook user data after exchanging the code for a token.
     *
     * @param string $code Authorization code from Facebook.
     * @throws Exception If token or user info retrieval fails.
     * @return array User data array.
     */
    private function get_facebook_user_data(string $code): array
    {
        // Exchange code for access token.
        // Ensure correct Facebook API version (check documentation for current).
        $token_url    = 'https://graph.facebook.com/v18.0/oauth/access_token';
        $token_params = [
            'client_id'     => $this->facebook_app_id,
            'client_secret' => $this->facebook_app_secret,
            'code'          => $code,
            'redirect_uri'  => $this->redirect_uri . '&provider=facebook',
        ];

        $response = wp_remote_get($token_url . '?' . http_build_query($token_params));

        if (is_wp_error($response)) {
            throw new Exception('Failed to get Facebook access token: ' . $response->get_error_message());
        }

        $token_data = json_decode(wp_remote_retrieve_body($response), true);

        if (!isset($token_data['access_token'])) {
            $error_message = $token_data['error']['message'] ?? 'Unknown error';
            throw new Exception('Failed to get Facebook access token: ' . $error_message);
        }

        // Get user info.
        // Ensure correct Facebook API version (check documentation for current).
        $user_info_url    = 'https://graph.facebook.com/v18.0/me';
        $user_info_params = [
            'fields'       => 'id,email,first_name,last_name,name', // Specify required fields.
            'access_token' => $token_data['access_token'],
        ];

        $user_info_response = wp_remote_get($user_info_url . '?' . http_build_query($user_info_params));

        if (is_wp_error($user_info_response)) {
            throw new Exception('Failed to get Facebook user info: ' . $user_info_response->get_error_message());
        }

        $user_info = json_decode(wp_remote_retrieve_body($user_info_response), true);

        return [
            'email'        => $user_info['email'] ?? '', // Email might not be returned if user denies permission.
            'first_name'   => $user_info['first_name'] ?? '',
            'last_name'    => $user_info['last_name'] ?? '',
            'display_name' => $user_info['name'] ?? '',
            'provider'     => 'facebook',
            'provider_id'  => $user_info['id'] ?? '',
        ];
    }

    /**
     * Login or create a user based on social login data.
     *
     * @param array $user_data User data from the provider.
     * @throws Exception If user creation fails.
     * @return void
     */
    private function login_or_create_user(array $user_data): void
    {
        $user = get_user_by('email', $user_data['email']);

        if (!$user) {
            // Create a new user.
            $username = $this->generate_unique_username($user_data['email']);

            $user_id = wp_create_user($username, wp_generate_password(), $user_data['email']);

            if (is_wp_error($user_id)) {
                throw new Exception('Failed to create user: ' . $user_id->get_error_message());
            }

            // Update user meta with details from social profile.
            wp_update_user(
                [
                    'ID'           => $user_id,
                    'first_name'   => $user_data['first_name'],
                    'last_name'    => $user_data['last_name'],
                    'display_name' => $user_data['display_name'],
                ]
            );

            update_user_meta($user_id, 'social_login_provider', $user_data['provider']);
            update_user_meta($user_id, 'social_login_provider_id', $user_data['provider_id']);

            $user = get_user_by('id', $user_id);

            // Optionally, send the new user notification.
            // wp_new_user_notification($user_id, null, 'user'); // or 'both'
        } else {
            // Optional: Update existing user's meta if needed (e.g., refresh provider ID).
            update_user_meta($user->ID, 'social_login_provider', $user_data['provider']);
            update_user_meta($user->ID, 'social_login_provider_id', $user_data['provider_id']);
        }

        // Log the user in.
        wp_set_current_user($user->ID); // Ensure the user context is set before setting the cookie.
        wp_set_auth_cookie($user->ID, true);

        // Redirect to admin dashboard or home page based on capabilities.
        $redirect_url = user_can($user->ID, 'manage_options') ? admin_url() : home_url();
        wp_safe_redirect($redirect_url);
        exit;
    }

    /**
     * Generate a unique username based on email prefix.
     * Appends numbers if the username already exists.
     *
     * @param string $email User's email address.
     * @return string A unique username.
     */
    private function generate_unique_username(string $email): string
    {
        $email_parts       = explode('@', $email);
        $username          = sanitize_user(current($email_parts), true);
        // Ensure username is not empty after sanitization.
        if (empty($username)) {
             $username = 'user' . time(); // Fallback username.
        }
        $original_username = $username;
        $i                 = 1;

        while (username_exists($username)) {
            $username = $original_username . $i;
            $i++;
        }

        return $username;
    }

    /**
     * Enqueue scripts and styles. (Currently only Dashicons).
     *
     * @return void
     */
    public function enqueue_scripts(): void
    {
        // Enqueue Dashicons for potential use in buttons or UI elements.
        wp_enqueue_style('dashicons');
    }

    /**
     * Register plugin settings.
     *
     * @return void
     */
    public function register_settings(): void
    {
        register_setting('wp_social_auth_settings', 'wp_social_auth_google_client_id', ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('wp_social_auth_settings', 'wp_social_auth_google_client_secret', ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('wp_social_auth_settings', 'wp_social_auth_facebook_app_id', ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('wp_social_auth_settings', 'wp_social_auth_facebook_app_secret', ['sanitize_callback' => 'sanitize_text_field']);
    }

    /**
     * Add settings page to the WordPress admin menu.
     *
     * @return void
     */
    public function add_settings_page(): void
    {
        add_options_page(
            'Social Login Settings', // Page title.
            'Social Login', // Menu title.
            'manage_options', // Capability required.
            'wp-social-auth-settings', // Menu slug.
            [$this, 'render_settings_page'] // Function to display the page content.
        );
    }

    /**
     * Render the settings page HTML.
     *
     * @return void
     */
    public function render_settings_page(): void
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
                <p>Register your application at <a href="https://console.developers.google.com/" target="_blank" rel="noopener noreferrer">Google Cloud Console</a> to get these credentials.</p>
                <p>Your authorized redirect URI is: <code><?php echo esc_html($this->redirect_uri . '&provider=google'); ?></code></p>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="wp_social_auth_google_client_id">Client ID</label></th>
                        <td>
                            <input type="text" id="wp_social_auth_google_client_id" name="wp_social_auth_google_client_id" value="<?php echo esc_attr(get_option('wp_social_auth_google_client_id')); ?>" class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="wp_social_auth_google_client_secret">Client Secret</label></th>
                        <td>
                            <input type="password" id="wp_social_auth_google_client_secret" name="wp_social_auth_google_client_secret" value="<?php echo esc_attr(get_option('wp_social_auth_google_client_secret')); ?>" class="regular-text" />
                        </td>
                    </tr>
                </table>

                <h2>Facebook Authentication</h2>
                <p>Register your application at <a href="https://developers.facebook.com/apps/" target="_blank" rel="noopener noreferrer">Facebook for Developers</a> to get these credentials.</p>
                 <p>Your valid OAuth redirect URI is: <code><?php echo esc_html($this->redirect_uri . '&provider=facebook'); ?></code></p>
               <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="wp_social_auth_facebook_app_id">App ID</label></th>
                        <td>
                            <input type="text" id="wp_social_auth_facebook_app_id" name="wp_social_auth_facebook_app_id" value="<?php echo esc_attr(get_option('wp_social_auth_facebook_app_id')); ?>" class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="wp_social_auth_facebook_app_secret">App Secret</label></th>
                        <td>
                            <input type="password" id="wp_social_auth_facebook_app_secret" name="wp_social_auth_facebook_app_secret" value="<?php echo esc_attr(get_option('wp_social_auth_facebook_app_secret')); ?>" class="regular-text" />
                        </td>
                    </tr>
                </table>

                <?php submit_button('Save Settings'); ?>
            </form>
        </div>
        <?php
    }
} // End class WP_Social_Auth

/**
 * Initializes the WP_Social_Auth plugin.
 * Retrieves settings from options and instantiates the main class.
 *
 * @param array $config Optional config override.
 * @return void
 */
function wp_social_auth_init(array $config = []): void
{
    // Get settings from options if not provided via config array.
    if (empty($config)) {
        $config = [
            'google_client_id'     => get_option('wp_social_auth_google_client_id'),
            'google_client_secret' => get_option('wp_social_auth_google_client_secret'),
            'facebook_app_id'      => get_option('wp_social_auth_facebook_app_id'),
            'facebook_app_secret'  => get_option('wp_social_auth_facebook_app_secret'),
        ];
    }

    // Initialize the plugin class.
    new WP_Social_Auth($config);
}

// Hook the initialization function to WordPress 'init' action.
add_action('plugins_loaded', 'wp_social_auth_init'); // Use plugins_loaded for options retrieval compatibility.