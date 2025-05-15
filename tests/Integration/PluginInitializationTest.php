<?php

namespace WordPressGmailCli\SocialAuth\Tests\Integration;

use WordPressGmailCli\SocialAuth\Plugin;
use WP_Mock;

/**
 * Test plugin initialization and component integration.
 */
class PluginInitializationTest extends TestCase
{
    /**
     * Test that the plugin initializes correctly with all components.
     */
    public function testPluginInitialization(): void
    {
        // Mock WordPress plugin and admin hooks
        WP_Mock::userFunction('plugin_dir_path')
            ->andReturn(dirname(dirname(__DIR__)) . '/');
        
        WP_Mock::userFunction('plugin_dir_url')
            ->andReturn('https://example.com/wp-content/plugins/wordpress-gmail-cli/');
        
        WP_Mock::userFunction('plugin_basename')
            ->andReturn('wordpress-gmail-cli/wp-social-auth.php');
        
        // Expect the plugin to register hooks
        WP_Mock::expectActionAdded('plugins_loaded', [WP_Mock\Functions::type('callable'), 'initPlugin']);
        WP_Mock::expectFilterAdded('plugin_action_links_wordpress-gmail-cli/wp-social-auth.php', [WP_Mock\Functions::type('callable'), 'addPluginLinks']);
        
        // Test that WordPress translatable strings are registered
        WP_Mock::userFunction('load_plugin_textdomain')
            ->once()
            ->with('wordpress-gmail-cli', false, WP_Mock\Functions::type('string'));
        
        // Initialize the plugin
        $plugin = new Plugin();
        $plugin->register();
        
        // Verify mock expectations
        $this->assertConditionsMet();
    }
    
    /**
     * Test that all components are properly integrated.
     */
    public function testComponentIntegration(): void
    {
        // Mock WordPress functions needed for initialization
        WP_Mock::userFunction('plugin_dir_path')
            ->andReturn(dirname(dirname(__DIR__)) . '/');
        
        WP_Mock::userFunction('plugin_dir_url')
            ->andReturn('https://example.com/wp-content/plugins/wordpress-gmail-cli/');
        
        // Mock options
        WP_Mock::userFunction('get_option')
            ->with('wp_social_auth_settings', WP_Mock\Functions::type('array'))
            ->andReturn([
                'providers' => [
                    'google' => [
                        'enabled' => true,
                        'client_id' => 'test-client-id',
                        'client_secret' => 'test-client-secret',
                    ]
                ]
            ]);
        
        // Initialize the plugin
        $plugin = new Plugin();
        
        // Access protected property using reflection
        $reflectionClass = new \ReflectionClass(Plugin::class);
        $configProperty = $reflectionClass->getProperty('config');
        $configProperty->setAccessible(true);
        
        // Verify the configuration is properly loaded
        $config = $configProperty->getValue($plugin);
        $this->assertNotNull($config);
        
        // Verify that provider factory is integrated
        $providerFactoryProperty = $reflectionClass->getProperty('providerFactory');
        $providerFactoryProperty->setAccessible(true);
        
        $providerFactory = $providerFactoryProperty->getValue($plugin);
        $this->assertNotNull($providerFactory);
        
        // Verify that logger is integrated
        $loggerProperty = $reflectionClass->getProperty('logger');
        $loggerProperty->setAccessible(true);
        
        $logger = $loggerProperty->getValue($plugin);
        $this->assertNotNull($logger);
    }
    
    /**
     * Test the loading of plugin textdomain for internationalization.
     */
    public function testPluginTextdomainLoading(): void
    {
        // Mock WordPress functions
        WP_Mock::userFunction('plugin_dir_path')
            ->andReturn(dirname(dirname(__DIR__)) . '/');
            
        WP_Mock::userFunction('plugin_basename')
            ->andReturn('wordpress-gmail-cli/wp-social-auth.php');
        
        // Set expectations for textdomain loading
        WP_Mock::userFunction('load_plugin_textdomain')
            ->once()
            ->with('wordpress-gmail-cli', false, 'wordpress-gmail-cli/languages');
        
        // Initialize the plugin
        $plugin = new Plugin();
        
        // Simulate loading translations
        $initCallback = null;
        
        WP_Mock::userFunction('add_action')
            ->with('plugins_loaded', WP_Mock\Functions::type('callable'))
            ->andReturnUsing(function($hook, $callback) use (&$initCallback) {
                $initCallback = $callback;
                return true;
            });
        
        $plugin->register();
        
        // Execute the callback that should load textdomain
        if (is_callable($initCallback)) {
            call_user_func($initCallback);
        }
        
        // Verify that all mock expectations were met
        $this->assertConditionsMet();
    }
}