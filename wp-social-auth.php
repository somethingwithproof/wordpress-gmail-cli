<?php
/**
 * Plugin Name: WordPress Social Authentication
 * Description: Adds Google and Facebook authentication to WordPress login
 * Version: 1.1.0
 * Author: WordPress Gmail CLI
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class WP_Social_Auth {
    private $google_client_id;
    private $google_client_secret;
    private $facebook_app_id;
    private $facebook_app_secret;
    private $redirect_uri;
    
    public function __construct($config) {
        $this->google_client_id = $config['google_client_id'] ?? '';
        $this->google_client_secret = $config['google_client_secret'] ?? '';
        $this->facebook_app_id = $config['facebook_app_id'] ?? '';
        $this->facebook_app_secret = $config['facebook_app_secret'] ?? '';
        $this->redirect_uri = admin_url('admin-ajax.php?action=social_login_callback');
        
        // Initialize hooks
        add_action('login_form', array($this, 'add_social_login_buttons'));
        add_action('wp_ajax_nopriv_social_login_callback', array($this, 'handle_social_login_callback'));
        add_action('wp_ajax_social_login_callback', array($this, 'handle_social_login_callback'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('login_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_menu', array($this, 'add_settings_page'));
    }
    
    /**
     * Add social login buttons to the WordPress login form
     */
    public function add_social_login_buttons() {
        ?>
        <div class="social-login-buttons" style="margin-bottom: 20px; text-align: center;">
            <?php if ($this->google_client_id): ?>
            <a href="<?php echo $this->get_google_auth_url(); ?>" class="button" style="background: #4285F4; color: white; margin-right: 10px; text-decoration: none; padding: 8px 12px; border-radius: 4px;">
                <span style="font-size: 16px; vertical-align: middle;">G</span> Login with Google
            </a>
            <?php endif; ?>
            
            <?php if ($this->facebook_app_id): ?>
            <a href="<?php echo $this->get_facebook_auth_url(); ?>" class="button" style="background: #3b5998; color: white; text-decoration: none; padding: 8px 12px; border-radius: 4px;">
                <span style="font-size: 16px; vertical-align: middle;">f</span> Login with Facebook
            </a>
            <?php endif; ?>
        </div>
        <?php
    }
    
    /**
     * Handle the social login callback
     */
    public function handle_social_login_callback() {
        // Verify nonce for security
        $provider = isset($_GET['provider']) ? sanitize_text_field($_GET['provider']) : '';
        $code = isset($_GET['code']) ? sanitize_text_field($_GET['code']) : '';
        $state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';
        
        // Validate provider
        if (!in_array($provider, ['google', 'facebook'], true)) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        
        // Verify state parameter to prevent CSRF
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
                wp_safe_redirect(wp_login_url() . '?login=failed');
                exit;
            }
        } catch (Exception $e) {
            // Don't expose detailed error messages to users
            error_log('Social login error: ' . $e->getMessage());
            wp_safe_redirect(wp_login_url() . '?login=failed');
            exit;
        }
    }
    
    /**
     * Get Google authentication URL
     */
    private function get_google_auth_url() {
        $params = array(
            'client_id' => $this->google_client_id,
            'redirect_uri' => $this->redirect_uri . '&provider=google',
            'response_type' => 'code',
            'scope' => 'email profile',
            'access_type' => 'online',
            'state' => wp_create_nonce('google_login')
        );
        
        return 'https://accounts.google.com/o/oauth2/auth?' . http_build_query($params);
    }
    
    /**
     * Get Facebook authentication URL
     */
    private function get_facebook_auth_url() {
        $params = array(
            'client_id' => $this->facebook_app_id,
            'redirect_uri' => $this->redirect_uri . '&provider=facebook',
            'response_type' => 'code',
            'scope' => 'email',
            'state' => wp_create_nonce('facebook_login')
        );
        
        return 'https://www.facebook.com/v12.0/dialog/oauth?' . http_build_query($params);
    }
    
    /**
     * Get Google user data
     */
    private function get_google_user_data($code) {
        // Exchange code for access token
        $token_url = 'https://oauth2.googleapis.com/token';
        $token_params = array(
            'client_id' => $this->google_client_id,
            'client_secret' => $this->google_client_secret,
            'code' => $code,
            'redirect_uri' => $this->redirect_uri . '&provider=google',
            'grant_type' => 'authorization_code'
        );
        
        $response = wp_remote_post($token_url, array(
            'body' => $token_params,
            'headers' => array('Content-Type' => 'application/x-www-form-urlencoded')
        ));
        
        if (is_wp_error($response)) {
            throw new Exception('Failed to get access token: ' . $response->get_error_message());
        }
        
        $token_data = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!isset($token_data['access_token'])) {
            throw new Exception('Failed to get access token');
        }
        
        // Get user info
        $user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo';
        $user_info_response = wp_remote_get($user_info_url, array(
            'headers' => array('Authorization' => 'Bearer ' . $token_data['access_token'])
        ));
        
        if (is_wp_error($user_info_response)) {
            throw new Exception('Failed to get user info: ' . $user_info_response->get_error_message());
        }
        
        $user_info = json_decode(wp_remote_retrieve_body($user_info_response), true);
        
        return array(
            'email' => $user_info['email'] ?? '',
            'first_name' => $user_info['given_name'] ?? '',
            'last_name' => $user_info['family_name'] ?? '',
            'display_name' => $user_info['name'] ?? '',
            'provider' => 'google',
            'provider_id' => $user_info['sub'] ?? ''
        );
    }
    
    /**
     * Get Facebook user data
     */
    private function get_facebook_user_data($code) {
        // Exchange code for access token
        $token_url = 'https://graph.facebook.com/v12.0/oauth/access_token';
        $token_params = array(
            'client_id' => $this->facebook_app_id,
            'client_secret' => $this->facebook_app_secret,
            'code' => $code,
            'redirect_uri' => $this->redirect_uri . '&provider=facebook'
        );
        
        $response = wp_remote_get($token_url . '?' . http_build_query($token_params));
        
        if (is_wp_error($response)) {
            throw new Exception('Failed to get access token: ' . $response->get_error_message());
        }
        
        $token_data = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!isset($token_data['access_token'])) {
            throw new Exception('Failed to get access token');
        }
        
        // Get user info
        $user_info_url = 'https://graph.facebook.com/v12.0/me';
        $user_info_params = array(
            'fields' => 'id,email,first_name,last_name,name',
            'access_token' => $token_data['access_token']
        );
        
        $user_info_response = wp_remote_get($user_info_url . '?' . http_build_query($user_info_params));
        
        if (is_wp_error($user_info_response)) {
            throw new Exception('Failed to get user info: ' . $user_info_response->get_error_message());
        }
        
        $user_info = json_decode(wp_remote_retrieve_body($user_info_response), true);
        
        return array(
            'email' => $user_info['email'] ?? '',
            'first_name' => $user_info['first_name'] ?? '',
            'last_name' => $user_info['last_name'] ?? '',
            'display_name' => $user_info['name'] ?? '',
            'provider' => 'facebook',
            'provider_id' => $user_info['id'] ?? ''
        );
    }
    
    /**
     * Login or create a user based on social login data
     */
    private function login_or_create_user($user_data) {
        $user = get_user_by('email', $user_data['email']);
        
        if (!$user) {
            // Create a new user
            $username = $this->generate_unique_username($user_data['email']);
            
            $user_id = wp_create_user($username, wp_generate_password(), $user_data['email']);
            
            if (is_wp_error($user_id)) {
                throw new Exception('Failed to create user: ' . $user_id->get_error_message());
            }
            
            // Update user meta
            wp_update_user(array(
                'ID' => $user_id,
                'first_name' => $user_data['first_name'],
                'last_name' => $user_data['last_name'],
                'display_name' => $user_data['display_name']
            ));
            
            update_user_meta($user_id, 'social_login_provider', $user_data['provider']);
            update_user_meta($user_id, 'social_login_provider_id', $user_data['provider_id']);
            
            $user = get_user_by('id', $user_id);
        }
        
        // Log the user in
        wp_set_auth_cookie($user->ID, true);
        
        // Redirect to admin dashboard or home page
        if (user_can($user->ID, 'manage_options')) {
            wp_safe_redirect(admin_url());
        } else {
            wp_safe_redirect(home_url());
        }
        exit;
    }
    
    /**
     * Generate a unique username based on email
     */
    private function generate_unique_username($email) {
        $username = sanitize_user(current(explode('@', $email)), true);
        $original_username = $username;
        $i = 1;
        
        while (username_exists($username)) {
            $username = $original_username . $i;
            $i++;
        }
        
        return $username;
    }
    
    /**
     * Enqueue scripts and styles
     */
    public function enqueue_scripts() {
        wp_enqueue_style('dashicons');
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('wp_social_auth_settings', 'wp_social_auth_google_client_id');
        register_setting('wp_social_auth_settings', 'wp_social_auth_google_client_secret');
        register_setting('wp_social_auth_settings', 'wp_social_auth_facebook_app_id');
        register_setting('wp_social_auth_settings', 'wp_social_auth_facebook_app_secret');
    }
    
    /**
     * Add settings page
     */
    public function add_settings_page() {
        add_options_page(
            'Social Login Settings',
            'Social Login',
            'manage_options',
            'wp-social-auth-settings',
            array($this, 'render_settings_page')
        );
    }
    
    /**
     * Render settings page
     */
    public function render_settings_page() {
        ?>
        <div class="wrap">
            <h1>Social Login Settings</h1>
            <form method="post" action="options.php">
                <?php settings_fields('wp_social_auth_settings'); ?>
                <?php do_settings_sections('wp_social_auth_settings'); ?>
                
                <h2>Google Authentication</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Client ID</th>
                        <td>
                            <input type="text" name="wp_social_auth_google_client_id" value="<?php echo esc_attr(get_option('wp_social_auth_google_client_id')); ?>" class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Client Secret</th>
                        <td>
                            <input type="password" name="wp_social_auth_google_client_secret" value="<?php echo esc_attr(get_option('wp_social_auth_google_client_secret')); ?>" class="regular-text" />
                        </td>
                    </tr>
                </table>
                
                <h2>Facebook Authentication</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">App ID</th>
                        <td>
                            <input type="text" name="wp_social_auth_facebook_app_id" value="<?php echo esc_attr(get_option('wp_social_auth_facebook_app_id')); ?>" class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">App Secret</th>
                        <td>
                            <input type="password" name="wp_social_auth_facebook_app_secret" value="<?php echo esc_attr(get_option('wp_social_auth_facebook_app_secret')); ?>" class="regular-text" />
                        </td>
                    </tr>
                </table>
                
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}

// Initialize the plugin if WordPress is loaded
function wp_social_auth_init($config = []) {
    // Get settings from options if not provided
    if (empty($config)) {
        $config = [
            'google_client_id' => get_option('wp_social_auth_google_client_id'),
            'google_client_secret' => get_option('wp_social_auth_google_client_secret'),
            'facebook_app_id' => get_option('wp_social_auth_facebook_app_id'),
            'facebook_app_secret' => get_option('wp_social_auth_facebook_app_secret')
        ];
    }
    
    // Initialize the plugin
    new WP_Social_Auth($config);
}

// Hook to initialize the plugin
add_action('init', 'wp_social_auth_init');
