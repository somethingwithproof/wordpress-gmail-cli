<?php
/**
 * WordPress function mocks for testing outside of WordPress
 * 
 * @package WordPressGmailCli\SocialAuth
 */

// WordPress core functions
if (!function_exists('add_action')) {
    function add_action() {
        return true;
    }
}

if (!function_exists('add_filter')) {
    function add_filter() {
        return true; 
    }
}

if (!function_exists('apply_filters')) {
    function apply_filters($tag, $value) {
        return $value;
    }
}

if (!function_exists('do_action')) {
    function do_action() {
        return null;
    }
}

// Options API mocks
if (!function_exists('get_option')) {
    function get_option($option, $default = false) {
        // Use test data array to store option values during tests
        static $test_options = [];
        
        if (isset($test_options[$option])) {
            return $test_options[$option];
        }
        
        return $default;
    }
}

if (!function_exists('update_option')) {
    function update_option($option, $value, $autoload = null) {
        static $test_options = [];
        $test_options[$option] = $value;
        return true;
    }
}

if (!function_exists('delete_option')) {
    function delete_option($option) {
        static $test_options = [];
        if (isset($test_options[$option])) {
            unset($test_options[$option]);
        }
        return true;
    }
}

// Sanitization and escaping functions
if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str) {
        return trim(strip_tags($str));
    }
}

if (!function_exists('esc_html')) {
    function esc_html($text) {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_url_raw')) {
    function esc_url_raw($url) {
        return filter_var($url, FILTER_SANITIZE_URL);
    }
}

if (!function_exists('wp_kses_post')) {
    function wp_kses_post($content) {
        return $content; // Simple implementation for testing
    }
}

// Transient API mocks
if (!function_exists('set_transient')) {
    function set_transient($transient, $value, $expiration = 0) {
        static $transients = [];
        $transients[$transient] = [
            'value' => $value,
            'expiration' => time() + $expiration,
        ];
        return true;
    }
}

if (!function_exists('get_transient')) {
    function get_transient($transient) {
        static $transients = [];
        
        if (!isset($transients[$transient])) {
            return false;
        }
        
        // Check if transient has expired
        if ($transients[$transient]['expiration'] < time() && $transients[$transient]['expiration'] > 0) {
            unset($transients[$transient]);
            return false;
        }
        
        return $transients[$transient]['value'];
    }
}

if (!function_exists('delete_transient')) {
    function delete_transient($transient) {
        static $transients = [];
        if (isset($transients[$transient])) {
            unset($transients[$transient]);
        }
        return true;
    }
}

// WordPress utility functions
if (!function_exists('wp_parse_args')) {
    function wp_parse_args($args, $defaults = []) {
        if (is_object($args)) {
            $args = get_object_vars($args);
        } elseif (!is_array($args)) {
            parse_str($args, $args);
        }
        
        return array_merge($defaults, $args);
    }
}

if (!function_exists('wp_generate_password')) {
    function wp_generate_password($length = 12, $special_chars = true) {
        return substr(md5(rand()), 0, $length);
    }
}

// Define WordPress constants if not defined
if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}

if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 60 * MINUTE_IN_SECONDS);
}

if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 24 * HOUR_IN_SECONDS);
}

if (!defined('WEEK_IN_SECONDS')) {
    define('WEEK_IN_SECONDS', 7 * DAY_IN_SECONDS);
}

if (!defined('MONTH_IN_SECONDS')) {
    define('MONTH_IN_SECONDS', 30 * DAY_IN_SECONDS);
}

