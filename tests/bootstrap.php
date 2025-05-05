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

// Mock WordPress functions for tests if we're not in WordPress environment
if (!function_exists('add_action')) {
    require_once __DIR__ . '/wp-mock-functions.php';
}

// Add your custom bootstrap code here

