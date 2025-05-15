<?php
/**
 * PHPUnit bootstrap file
 *
 * @package WordPressGmailCli\SocialAuth
 */

// First, load Composer's autoloader.
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Define testing constants
if (!defined('WP_SOCIAL_AUTH_TESTING')) {
    define('WP_SOCIAL_AUTH_TESTING', true);
}

// Set up WP_Mock
WP_Mock::bootstrap();

// Additional WordPress mock constants - only define if not already defined
if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__FILE__) . '/dummy-wordpress/');
}
if (!defined('WP_DEBUG')) {
    define('WP_DEBUG', true);
}
if (!defined('WP_CONTENT_DIR')) {
    define('WP_CONTENT_DIR', ABSPATH . 'wp-content/');
}
if (!defined('WP_PLUGIN_DIR')) {
    define('WP_PLUGIN_DIR', WP_CONTENT_DIR . 'plugins/');
}
if (!defined('WPINC')) {
    define('WPINC', 'wp-includes');
}

// Load our simple mock functions for cases not covered by WP_Mock
require_once __DIR__ . '/wp-mock-functions.php';

// Add custom bootstrap code here

