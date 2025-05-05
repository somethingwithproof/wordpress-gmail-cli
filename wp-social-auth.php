<?php
/**
 * Plugin Name: WordPress Social Authentication
 * Plugin URI: https://github.com/wordpress-gmail-cli/wp-social-auth
 * Description: Secure social login for WordPress using Google and Facebook authentication.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: WordPress Gmail CLI
 * Author URI: https://github.com/wordpress-gmail-cli
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-social-auth
 * Domain Path: /languages
 *
 * @package WordPressGmailCli\SocialAuth
 */

// Prevent direct access to this file.
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants.
define('WP_SOCIAL_AUTH_VERSION', '1.0.0');
define('WP_SOCIAL_AUTH_FILE', __FILE__);
define('WP_SOCIAL_AUTH_PATH', plugin_dir_path(__FILE__));
define('WP_SOCIAL_AUTH_URL', plugin_dir_url(__FILE__));
define('WP_SOCIAL_AUTH_BASENAME', plugin_basename(__FILE__));

// Ensure composer autoloader exists.
$autoloader = __DIR__ . '/vendor/autoload.php';

if (!file_exists($autoloader)) {
    add_action('admin_notices', function() {
        $message = sprintf(
            /* translators: %s: composer command */
            __(
                'WordPress Social Authentication requires composer dependencies to be installed. Please run %s within the plugin directory.',
                'wp-social-auth'
            ),
            '<code>composer install</code>'
        );
        printf('<div class="notice notice-error"><p>%s</p></div>', wp_kses_post($message));
    });
    return;
}

require_once $autoloader;

// Initialize the plugin.
add_action('plugins_loaded', function() {
    try {
        // Check PHP version requirement.
        if (version_compare(PHP_VERSION, '7.4', '<')) {
            throw new \RuntimeException(
                sprintf(
                    'WordPress Social Authentication requires PHP 7.4 or higher. Your PHP version: %s',
                    PHP_VERSION
                )
            );
        }

        // Initialize plugin.
        \WP_Social_Auth\WP_Social_Auth_PlugingetInstance();
        
    } catch (\Exception $e) {
        // Log error and display admin notice.
        if (function_exists('error_log')) {
            error_log(sprintf(
                'WordPress Social Authentication initialization error: %s',
                $e->getMessage()
            ));
        }

        add_action('admin_notices', function() use ($e) {
            printf(
                '<div class="notice notice-error"><p>%s</p></div>',
                esc_html(sprintf(
                    'WordPress Social Authentication error: %s',
                    $e->getMessage()
                ))
            );
        });
    }
});

/**
 * Function to access plugin instance.
 *
 * @return \WP_Social_Auth\Plugin Plugin instance.
 */
function wp_social_auth(): \WP_Social_Auth\Plugin {
    return \WP_Social_Auth\WP_Social_Auth_PlugingetInstance();
}
