<?php

namespace WordPressGmailCli\SocialAuth\Tests\Functional;

use WordPressGmailCli\SocialAuth\Tests\TestCase as BaseTestCase;
use WordPressGmailCli\SocialAuth\Plugin;

/**
 * Base TestCase for functional tests.
 * 
 * Functional tests test complete user flows and real-world scenarios.
 */
abstract class TestCase extends BaseTestCase
{
    /**
     * @var Plugin
     */
    protected $plugin;
    
    /**
     * Set up for functional tests
     * 
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Mock WordPress core functions
        $this->setupWordPressMocksForFunctionalTests();
        
        // Create a fresh plugin instance for each test
        $this->plugin = new Plugin();
    }
    
    /**
     * Set up WordPress mocks for functional tests
     * 
     * @return void
     */
    protected function setupWordPressMocksForFunctionalTests(): void
    {
        // Mock WordPress hook system
        \WP_Mock::userFunction('add_action')->andReturn(true);
        \WP_Mock::userFunction('add_filter')->andReturn(true);
        \WP_Mock::userFunction('do_action')->andReturn(null);
        \WP_Mock::userFunction('apply_filters')->andReturnFirstArg();
        
        // Mock WordPress options API with a more complete implementation
        \WP_Mock::userFunction('get_option')->andReturnUsing(function($option, $default = false) {
            static $options = [];
            return $options[$option] ?? $default;
        });
        
        \WP_Mock::userFunction('update_option')->andReturnUsing(function($option, $value) {
            static $options = [];
            $options[$option] = $value;
            return true;
        });
        
        \WP_Mock::userFunction('delete_option')->andReturnUsing(function($option) {
            static $options = [];
            if (isset($options[$option])) {
                unset($options[$option]);
            }
            return true;
        });
        
        // Mock WordPress transient API
        \WP_Mock::userFunction('set_transient')->andReturnUsing(function($transient, $value, $expiration = 0) {
            static $transients = [];
            $transients[$transient] = [
                'value' => $value,
                'expiration' => time() + $expiration,
            ];
            return true;
        });
        
        \WP_Mock::userFunction('get_transient')->andReturnUsing(function($transient) {
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
        });
        
        // Mock WordPress essential functions
        \WP_Mock::userFunction('plugin_dir_path')->andReturn(dirname(dirname(__DIR__)) . '/');
        \WP_Mock::userFunction('plugin_dir_url')->andReturn('https://example.com/wp-content/plugins/wordpress-gmail-cli/');
        \WP_Mock::userFunction('plugin_basename')->andReturn('wordpress-gmail-cli/wp-social-auth.php');
        
        // Mock WordPress user functions
        \WP_Mock::userFunction('is_user_logged_in')->andReturn(false);
        \WP_Mock::userFunction('wp_get_current_user')->andReturn((object) [
            'ID' => 0,
            'user_login' => '',
            'user_email' => '',
        ]);
    }
}