<?php

namespace WordPressGmailCli\SocialAuth\Tests\Unit;

use Mockery;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use WordPressGmailCli\SocialAuth\Authentication\AuthenticationManager;
use WordPressGmailCli\SocialAuth\Configuration\Configuration;
use WordPressGmailCli\SocialAuth\Plugin;
use WordPressGmailCli\SocialAuth\Providers\ProviderFactory;
use WordPressGmailCli\SocialAuth\Settings\SettingsManager;
use WordPressGmailCli\SocialAuth\UserManagement\UserManager;

/**
 * Test case for the Plugin class.
 */
class PluginTest extends TestCase
{
    /**
     * @var Plugin
     */
    private $plugin;
    
    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Define necessary constants for testing
        if (!defined('WP_SOCIAL_AUTH_VERSION')) {
            define('WP_SOCIAL_AUTH_VERSION', '1.0.0');
        }
        
        if (!defined('WP_SOCIAL_AUTH_FILE')) {
            define('WP_SOCIAL_AUTH_FILE', '/path/to/plugin/wp-social-auth.php');
        }
        
        if (!defined('WP_SOCIAL_AUTH_PATH')) {
            define('WP_SOCIAL_AUTH_PATH', '/path/to/plugin/');
        }
        
        if (!defined('WP_SOCIAL_AUTH_URL')) {
            define('WP_SOCIAL_AUTH_URL', 'https://example.com/wp-content/plugins/wp-social-auth/');
        }
        
        if (!defined('WP_SOCIAL_AUTH_BASENAME')) {
            define('WP_SOCIAL_AUTH_BASENAME', 'wp-social-auth/wp-social-auth.php');
        }
        
        // Get the singleton instance
        $this->plugin = Plugin::getInstance();
    }
    
    /**
     * Clean up after tests.
     */
    protected function tearDown(): void
    {
        // Reset the singleton instance using reflection
        $reflectionClass = new \ReflectionClass(Plugin::class);
        $reflectionProperty = $reflectionClass->getProperty('instance');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue(null, null);
        
        Mockery::close();
        parent::tearDown();
    }
    
    /**
     * Test getting singleton instance.
     */
    public function testGetInstance(): void
    {
        $instance1 = Plugin::getInstance();
        $instance2 = Plugin::getInstance();
        
        $this->assertSame($instance1, $instance2);
        $this->assertInstanceOf(Plugin::class, $instance1);
    }
    
    /**
     * Test getting the plugin version.
     */
    public function testGetVersion(): void
    {
        $version = $this->plugin->getVersion();
        $this->assertEquals('1.0.0', $version);
    }
    
    /**
     * Test getting the configuration instance.
     */
    public function testGetConfig(): void
    {
        $config = $this->plugin->getConfig();
        $this->assertInstanceOf(Configuration::class, $config);
    }
    
    /**
     * Test getting the logger instance.
     */
    public function testGetLogger(): void
    {
        $logger = $this->plugin->getLogger();
        $this->assertInstanceOf(LoggerInterface::class, $logger);
    }
    
    /**
     * Test getting the provider factory instance.
     */
    public function testGetProviderFactory(): void
    {
        $factory = $this->plugin->getProviderFactory();
        $this->assertInstanceOf(ProviderFactory::class, $factory);
    }
    
    /**
     * Test getting the authentication manager instance.
     */
    public function testGetAuthenticationManager(): void
    {
        // We need to mock the AuthenticationManager class because it's likely complex
        // with dependencies that are hard to set up in a unit test
        
        // Create a mock function for the constructor
        $mockAuthManager = Mockery::mock(AuthenticationManager::class);
        
        // Use reflection to replace the private property
        $reflectionClass = new \ReflectionClass($this->plugin);
        $reflectionProperty = $reflectionClass->getProperty('authenticationManager');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->plugin, $mockAuthManager);
        
        $authManager = $this->plugin->getAuthenticationManager();
        $this->assertSame($mockAuthManager, $authManager);
    }
    
    /**
     * Test getting the user manager instance.
     */
    public function testGetUserManager(): void
    {
        // Create a mock for the UserManager
        $mockUserManager = Mockery::mock(UserManager::class);
        
        // Use reflection to replace the private property
        $reflectionClass = new \ReflectionClass($this->plugin);
        $reflectionProperty = $reflectionClass->getProperty('userManager');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->plugin, $mockUserManager);
        
        $userManager = $this->plugin->getUserManager();
        $this->assertSame($mockUserManager, $userManager);
    }
    
    /**
     * Test getting the settings manager instance.
     */
    public function testGetSettingsManager(): void
    {
        // Create a mock for the SettingsManager
        $mockSettingsManager = Mockery::mock(SettingsManager::class);
        
        // Use reflection to replace the private property
        $reflectionClass = new \ReflectionClass($this->plugin);
        $reflectionProperty = $reflectionClass->getProperty('settingsManager');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->plugin, $mockSettingsManager);
        
        $settingsManager = $this->plugin->getSettingsManager();
        $this->assertSame($mockSettingsManager, $settingsManager);
    }
    
    /**
     * Test the plugin activation process with valid environment.
     */
    public function testActivateWithValidEnvironment(): void
    {
        // Mock the config
        $mockConfig = Mockery::mock(Configuration::class);
        $mockConfig->shouldReceive('get')
            ->with('plugin.min_php_version', '7.4')
            ->andReturn('7.4');
        $mockConfig->shouldReceive('get')
            ->with('plugin.min_wp_version', '5.8')
            ->andReturn('5.8');
        $mockConfig->shouldReceive('save')
            ->andReturn(true);
        
        // Set the global WP version
        global $wp_version;
        $wp_version = '5.9';
        
        // Use reflection to replace the private property
        $reflectionClass = new \ReflectionClass($this->plugin);
        $reflectionProperty = $reflectionClass->getProperty('config');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->plugin, $mockConfig);
        
        // Call activate
        $this->plugin->activate();
        
        // Success is just that no exception was thrown
        $this->assertTrue(true);
    }
    
    /**
     * Test the plugin activation with incompatible PHP version.
     */
    public function testActivateWithIncompatiblePhpVersion(): void
    {
        // Mock the config
        $mockConfig = Mockery::mock(Configuration::class);
        $mockConfig->shouldReceive('get')
            ->with('plugin.min_php_version', '7.4')
            ->andReturn('999.0'); // An impossible PHP version
        
        // Use reflection to replace the private property
        $reflectionClass = new \ReflectionClass($this->plugin);
        $reflectionProperty = $reflectionClass->getProperty('config');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->plugin, $mockConfig);
        
        // Since wp_die would exit, we need to simulate it differently
        // We'll use a mock to capture it
        global $wp_die_called;
        $wp_die_called = false;
        
        // Call activate - it should call wp_die but we've mocked it
        $this->plugin->activate();
        
        // Check that wp_die was called
        $this->assertTrue($wp_die_called);
    }
    
    /**
     * Test the plugin activation with incompatible WordPress version.
     */
    public function testActivateWithIncompatibleWpVersion(): void
    {
        // Mock the config
        $mockConfig = Mockery::mock(Configuration::class);
        $mockConfig->shouldReceive('get')
            ->with('plugin.min_php_version', '7.4')
            ->andReturn('7.4');
        $mockConfig->shouldReceive('get')
            ->with('plugin.min_wp_version', '5.8')
            ->andReturn('999.0'); // An impossible WP version
        
        // Set the global WP version
        global $wp_version;
        $wp_version = '5.9';
        
        // Use reflection to replace the private property
        $reflectionClass = new \ReflectionClass($this->plugin);
        $reflectionProperty = $reflectionClass->getProperty('config');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->plugin, $mockConfig);
        
        // Since wp_die would exit, we need to simulate it differently
        // We'll use a mock to capture it
        global $wp_die_called;
        $wp_die_called = false;
        
        // Call activate - it should call wp_die but we've mocked it
        $this->plugin->activate();
        
        // Check that wp_die was called
        $this->assertTrue($wp_die_called);
    }
    
    /**
     * Test the plugin deactivation process.
     */
    public function testDeactivate(): void
    {
        // Create a mock for the wpdb object
        global $wpdb;
        $wpdb = Mockery::mock('\wpdb');
        $wpdb->options = 'wp_options';
        
        $wpdb->shouldReceive('prepare')
            ->with("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", Mockery::any())
            ->andReturn('DELETE FROM wp_options WHERE option_name LIKE %s');
        
        $wpdb->shouldReceive('query')
            ->with('DELETE FROM wp_options WHERE option_name LIKE %s')
            ->andReturn(true);
        
        $wpdb->shouldReceive('esc_like')
            ->with('_transient_wp_social_auth_')
            ->andReturn('_transient_wp_social_auth_');
        
        // Call deactivate
        $this->plugin->deactivate();
        
        // Success is just that no exception was thrown
        $this->assertTrue(true);
    }
    
    /**
     * Test the plugin initialization process.
     */
    public function testInitPlugin(): void
    {
        // Mock the dependencies to avoid having to test them fully
        $mockUserManager = Mockery::mock(UserManager::class);
        $mockAuthManager = Mockery::mock(AuthenticationManager::class);
        
        // Set up the plugin with mocked components
        $pluginMock = Mockery::mock(Plugin::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        
        $pluginMock->shouldReceive('getUserManager')
            ->andReturn($mockUserManager);
        
        $pluginMock->shouldReceive('getAuthenticationManager')
            ->andReturn($mockAuthManager);
        
        $pluginMock->shouldReceive('runCompatibilityChecks')
            ->once()
            ->andReturn(true);
        
        // Call initPlugin
        $pluginMock->initPlugin();
        
        // Success is just that no exception was thrown and methods were called
        $this->assertTrue(true);
    }
    
    /**
     * Test the plugin initialization with an exception.
     */
    public function testInitPluginWithException(): void
    {
        // Mock the dependencies to throw an exception
        $pluginMock = Mockery::mock(Plugin::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        
        $pluginMock->shouldReceive('getUserManager')
            ->andThrow(new \Exception('Test exception'));
        
        // Mock the logger
        $mockLogger = Mockery::mock(LoggerInterface::class);
        $mockLogger->shouldReceive('error')
            ->once()
            ->with('Error initializing plugin', Mockery::any());
        
        // Set the logger
        $reflectionClass = new \ReflectionClass($pluginMock);
        $reflectionProperty = $reflectionClass->getProperty('logger');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($pluginMock, $mockLogger);
        
        // Call initPlugin - should log error but not throw
        $pluginMock->initPlugin();
        
        // Check that the admin notice action was added
        $this->assertTrue(has_action('admin_notices'));
    }
    
    /**
     * Test the plugin's compatibility checks.
     */
    public function testRunCompatibilityChecks(): void
    {
        // Extension_loaded is a built-in PHP function that can't be mocked easily
        // We'll use reflection to call the protected method directly
        
        // Also check the admin notice for SSL
        $this->assertFalse(has_action('admin_notices'));
        
        // Call the method using reflection
        $reflectionClass = new \ReflectionClass($this->plugin);
        $method = $reflectionClass->getMethod('runCompatibilityChecks');
        $method->setAccessible(true);
        $method->invoke($this->plugin);
        
        // If HTTPS is not available, an admin notice should be added
        $this->assertTrue(has_action('admin_notices'));
    }
}

// Mock WordPress functions required for testing
if (!function_exists('register_activation_hook')) {
    function register_activation_hook($file, $callback) {
        return true;
    }
}

if (!function_exists('register_deactivation_hook')) {
    function register_deactivation_hook($file, $callback) {
        return true;
    }
}

if (!function_exists('add_action')) {
    function add_action($hook, $callback, $priority = 10, $accepted_args = 1) {
        global $wp_actions;
        $wp_actions[$hook] = true;
        return true;
    }
}

if (!function_exists('has_action')) {
    function has_action($hook) {
        global $wp_actions;
        return isset($wp_actions[$hook]);
    }
}

if (!function_exists('add_filter')) {
    function add_filter($hook, $callback, $priority = 10, $accepted_args = 1) {
        return true;
    }
}

if (!function_exists('deactivate_plugins')) {
    function deactivate_plugins($plugin) {
        return true;
    }
}

if (!function_exists('plugin_basename')) {
    function plugin_basename($file) {
        return 'wp-social-auth/wp-social-auth.php';
    }
}

if (!function_exists('plugin_dir_url')) {
    function plugin_dir_url($file) {
        return 'https://example.com/wp-content/plugins/wp-social-auth/';
    }
}

if (!function_exists('wp_die')) {
    function wp_die($message, $title = '', $args = []) {
        global $wp_die_called;
        $wp_die_called = true;
        return null;
    }
}

if (!function_exists('is_admin')) {
    function is_admin() {
        return true;
    }
}

if (!function_exists('admin_url')) {
    function admin_url($path = '') {
        return 'https://example.com/wp-admin/' . $path;
    }
}

if (!function_exists('wp_enqueue_style')) {
    function wp_enqueue_style($handle, $src = '', $deps = [], $ver = false, $media = 'all') {
        return true;
    }
}

if (!function_exists('wp_safe_redirect')) {
    function wp_safe_redirect($location, $status = 302) {
        return true;
    }
}

if (!function_exists('wp_login_url')) {
    function wp_login_url($redirect = '') {
        return 'https://example.com/wp-login.php';
    }
}

if (!function_exists('add_query_arg')) {
    function add_query_arg($args, $url) {
        return $url . '?' . http_build_query($args);
    }
}

if (!function_exists('is_ssl')) {
    function is_ssl() {
        return false;
    }
}

if (!function_exists('wp_doing_ajax')) {
    function wp_doing_ajax() {
        return false;
    }
}

if (!function_exists('__')) {
    function __($text, $domain = 'default') {
        return $text;
    }
}

if (!function_exists('esc_html__')) {
    function esc_html__($text, $domain = 'default') {
        return htmlspecialchars($text);
    }
}

if (!function_exists('load_plugin_textdomain')) {
    function load_plugin_textdomain($domain, $deprecated = false, $plugin_rel_path = false) {
        return true;
    }
}

if (!function_exists('dirname')) {
    function dirname($path) {
        return pathinfo($path, PATHINFO_DIRNAME);
    }
}