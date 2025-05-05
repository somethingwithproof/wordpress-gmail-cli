<?php

namespace WordPressGmailCli\SocialAuth\Tests\Unit\Configuration;

use PHPUnit\Framework\TestCase;
use WordPressGmailCli\SocialAuth\Configuration\Configuration;
use WordPressGmailCli\SocialAuth\Exception\ConfigException;

/**
 * Test case for the Configuration class.
 */
class ConfigurationTest extends TestCase
{
    /**
     * @var Configuration
     */
    private Configuration $config;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Create a fresh configuration instance for each test
        $this->config = new Configuration();
    }

    /**
     * Test that default configuration values are set correctly.
     */
    public function testDefaultValues(): void
    {
        // Check plugin defaults
        $this->assertEquals('1.0.0', $this->config->get('plugin.version'));
        $this->assertEquals('5.8', $this->config->get('plugin.min_wp_version'));
        $this->assertEquals('7.4', $this->config->get('plugin.min_php_version'));
        
        // Check provider defaults
        $this->assertTrue($this->config->get('providers.google.enabled'));
        $this->assertEquals('Sign in with Google', $this->config->get('providers.google.label'));
        $this->assertFalse($this->config->get('providers.facebook.enabled'));
        
        // Check security defaults
        $this->assertTrue($this->config->get('security.rate_limit.enabled'));
        $this->assertEquals(5, $this->config->get('security.rate_limit.max_attempts'));
        $this->assertEquals(300, $this->config->get('security.rate_limit.window'));
    }

    /**
     * Test the get method with existing and non-existing keys.
     */
    public function testGet(): void
    {
        // Test getting existing key
        $this->assertEquals('1.0.0', $this->config->get('plugin.version'));
        
        // Test getting non-existing key with default value
        $this->assertEquals('default', $this->config->get('non.existing.key', 'default'));
        
        // Test getting non-existing key without default value
        $this->assertNull($this->config->get('non.existing.key'));
    }

    /**
     * Test the set method.
     */
    public function testSet(): void
    {
        // Test setting a new value
        $this->config->set('test.key', 'test_value');
        $this->assertEquals('test_value', $this->config->get('test.key'));
        
        // Test overwriting an existing value
        $this->config->set('plugin.version', '2.0.0');
        $this->assertEquals('2.0.0', $this->config->get('plugin.version'));
        
        // Test setting nested values
        $this->config->set('nested.key1.key2.key3', 'nested_value');
        $this->assertEquals('nested_value', $this->config->get('nested.key1.key2.key3'));
        
        // Test that the set method is chainable
        $result = $this->config->set('chainable.test', true);
        $this->assertInstanceOf(Configuration::class, $result);
    }

    /**
     * Test the getAs method for type casting.
     */
    public function testGetAs(): void
    {
        // Test boolean casting
        $this->config->set('test.bool', '1');
        $this->assertTrue($this->config->getAs('test.bool', 'bool'));
        
        $this->config->set('test.bool', '0');
        $this->assertFalse($this->config->getAs('test.bool', 'bool'));
        
        // Test integer casting
        $this->config->set('test.int', '123');
        $this->assertSame(123, $this->config->getAs('test.int', 'int'));
        
        // Test float casting
        $this->config->set('test.float', '123.45');
        $this->assertSame(123.45, $this->config->getAs('test.float', 'float'));
        
        // Test string casting
        $this->config->set('test.string', 123);
        $this->assertSame('123', $this->config->getAs('test.string', 'string'));
        
        // Test array casting
        $this->config->set('test.array', 'not_an_array');
        $this->assertIsArray($this->config->getAs('test.array', 'array'));
    }

    /**
     * Test the has method.
     */
    public function testHas(): void
    {
        // Test existing key
        $this->assertTrue($this->config->has('plugin.version'));
        
        // Test non-existing key
        $this->assertFalse($this->config->has('non.existing.key'));
        
        // Test after setting a new key
        $this->config->set('new.key', 'value');
        $this->assertTrue($this->config->has('new.key'));
    }

    /**
     * Test the getProviderConfig method.
     */
    public function testGetProviderConfig(): void
    {
        // Test getting valid provider config
        $googleConfig = $this->config->getProviderConfig('google');
        $this->assertIsArray($googleConfig);
        $this->assertTrue($googleConfig['enabled']);
        
        // Test getting config for a disabled provider
        $this->expectException(ConfigException::class);
        $this->config->getProviderConfig('facebook');
    }

    /**
     * Test the getEnabledProviders method.
     */
    public function testGetEnabledProviders(): void
    {
        // By default, only Google should be enabled
        $enabledProviders = $this->config->getEnabledProviders();
        $this->assertCount(1, $enabledProviders);
        $this->assertArrayHasKey('google', $enabledProviders);
        
        // Enable Facebook and check again
        $this->config->set('providers.facebook.enabled', true);
        $enabledProviders = $this->config->getEnabledProviders();
        $this->assertCount(2, $enabledProviders);
        $this->assertArrayHasKey('facebook', $enabledProviders);
    }

    /**
     * Test environment variable loading.
     */
    public function testEnvironmentVariableLoading(): void
    {
        // Set environment variables
        putenv('WP_SOCIAL_AUTH_GOOGLE_CLIENT_ID=test_client_id');
        putenv('WP_SOCIAL_AUTH_SECURITY_RATE_LIMIT_ENABLED=false');
        
        // Create a new configuration instance to pick up environment variables
        $config = new Configuration();
        
        // Check that environment variables were loaded
        $this->assertEquals('test_client_id', $config->get('providers.google.client_id'));
        $this->assertFalse($config->get('security.rate_limit.enabled'));
        
        // Clean up environment variables
        putenv('WP_SOCIAL_AUTH_GOOGLE_CLIENT_ID');
        putenv('WP_SOCIAL_AUTH_SECURITY_RATE_LIMIT_ENABLED');
    }

    /**
     * Test configuration merging.
     */
    public function testConfigurationMerging(): void
    {
        // Create configuration with custom values
        $config = new Configuration([
            'custom' => [
                'key' => 'value',
            ],
            'plugin' => [
                'version' => '2.0.0',
            ],
        ]);
        
        // Check that custom values were merged with defaults
        $this->assertEquals('value', $config->get('custom.key'));
        $this->assertEquals('2.0.0', $config->get('plugin.version'));
        $this->assertEquals('5.8', $config->get('plugin.min_wp_version')); // Default value preserved
    }

    /**
     * Test the toArray method.
     */
    public function testToArray(): void
    {
        // Convert the configuration to array
        $configArray = $this->config->toArray();
        
        // Check that it's an array
        $this->assertIsArray($configArray);
        
        // Check that values in the array match the configuration
        $this->assertEquals('1.0.0', $configArray['plugin']['version']);
        
        // Set a custom value and check it appears in the array
        $this->config->set('test.key', 'value');
        $configArray = $this->config->toArray();
        $this->assertEquals('value', $configArray['test']['key']);
    }
}

