<?php

namespace WordPressGmailCli\SocialAuth\Tests\Unit\Configuration;

use PHPUnit\Framework\TestCase;
use WordPressGmailCli\SocialAuth\Configuration\Configuration;
use WordPressGmailCli\SocialAuth\Exception\ConfigException;

/**
 * Extended test case for the Configuration class.
 * This tests additional functionality beyond what's covered in ConfigurationTest.
 */
class ConfigurationExtendedTest extends TestCase
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
     * Test the remove method.
     */
    public function testRemove(): void
    {
        // Set a value and verify it exists
        $this->config->set('test.key', 'value');
        $this->assertTrue($this->config->has('test.key'));

        // Remove the value
        $result = $this->config->remove('test.key');
        
        // Test that remove is chainable
        $this->assertInstanceOf(Configuration::class, $result);
        
        // Test that the key no longer exists
        $this->assertFalse($this->config->has('test.key'));
        $this->assertNull($this->config->get('test.key'));
    }

    /**
     * Test removing a nested key.
     */
    public function testRemoveNestedKey(): void
    {
        // Set nested values
        $this->config->set('parent.child1', 'value1');
        $this->config->set('parent.child2', 'value2');
        
        // Remove one child
        $this->config->remove('parent.child1');
        
        // Verify that only the specified child was removed
        $this->assertFalse($this->config->has('parent.child1'));
        $this->assertTrue($this->config->has('parent.child2'));
        $this->assertEquals('value2', $this->config->get('parent.child2'));
    }

    /**
     * Test removing a parent key removes all children.
     */
    public function testRemoveParentRemovesChildren(): void
    {
        // Set nested values
        $this->config->set('parent.child1', 'value1');
        $this->config->set('parent.child2', 'value2');
        
        // Remove the parent
        $this->config->remove('parent');
        
        // Verify that all children were removed
        $this->assertFalse($this->config->has('parent'));
        $this->assertFalse($this->config->has('parent.child1'));
        $this->assertFalse($this->config->has('parent.child2'));
    }

    /**
     * Test removing a non-existent key doesn't cause errors.
     */
    public function testRemoveNonExistentKey(): void
    {
        // Remove a key that doesn't exist
        $result = $this->config->remove('non.existent.key');
        
        // Should not cause errors and should be chainable
        $this->assertInstanceOf(Configuration::class, $result);
    }

    /**
     * Test the save and load methods.
     */
    public function testSaveAndLoad(): void
    {
        // Set custom values
        $this->config->set('test.key', 'test_value');
        
        // Save the configuration
        $this->config->save();
        
        // Create a new instance and it should load the saved values
        $newConfig = new Configuration();
        
        // Verify that the saved values were loaded
        $this->assertEquals('test_value', $newConfig->get('test.key'));
    }

    /**
     * Test setting invalid values.
     */
    public function testSetInvalidValues(): void
    {
        // Set a resource value (should be ignored)
        $resource = fopen('php://memory', 'r');
        $this->config->set('test.resource', $resource);
        
        // Should not be stored
        $this->assertNull($this->config->get('test.resource'));
        
        // Clean up
        fclose($resource);
        
        // Set a closure value (should be ignored)
        $closure = function() {};
        $this->config->set('test.closure', $closure);
        
        // Should not be stored
        $this->assertNull($this->config->get('test.closure'));
    }

    /**
     * Test getting a value with dot notation for array items.
     */
    public function testGetWithArrayAccess(): void
    {
        // Set an array value
        $this->config->set('test.array', ['item1', 'item2', 'item3']);
        
        // Access array items by index
        $this->assertEquals('item1', $this->config->get('test.array.0'));
        $this->assertEquals('item2', $this->config->get('test.array.1'));
        $this->assertEquals('item3', $this->config->get('test.array.2'));
        
        // Access non-existent index
        $this->assertNull($this->config->get('test.array.3'));
    }

    /**
     * Test getting a value with complex nested array access.
     */
    public function testGetWithComplexArrayAccess(): void
    {
        // Set a complex nested array
        $this->config->set('complex', [
            'level1' => [
                'level2' => [
                    'item1',
                    'item2' => [
                        'deep' => 'value'
                    ]
                ]
            ]
        ]);
        
        // Access deeply nested values
        $this->assertEquals('item1', $this->config->get('complex.level1.level2.0'));
        $this->assertEquals('value', $this->config->get('complex.level1.level2.item2.deep'));
    }

    /**
     * Test handling of boolean values in configuration.
     */
    public function testBooleanHandling(): void
    {
        // Set string values that represent booleans
        $this->config->set('test.true_string', 'true');
        $this->config->set('test.false_string', 'false');
        $this->config->set('test.yes_string', 'yes');
        $this->config->set('test.no_string', 'no');
        $this->config->set('test.one_string', '1');
        $this->config->set('test.zero_string', '0');
        
        // Check type conversion
        $this->assertTrue($this->config->getAs('test.true_string', 'bool'));
        $this->assertFalse($this->config->getAs('test.false_string', 'bool'));
        $this->assertTrue($this->config->getAs('test.yes_string', 'bool'));
        $this->assertFalse($this->config->getAs('test.no_string', 'bool'));
        $this->assertTrue($this->config->getAs('test.one_string', 'bool'));
        $this->assertFalse($this->config->getAs('test.zero_string', 'bool'));
    }

    /**
     * Test loading configurations from environment variables with prefixes.
     */
    public function testEnvironmentVariableWithCustomPrefix(): void
    {
        // Set environment variables with a custom prefix
        putenv('CUSTOM_PREFIX_TEST_VALUE=custom_value');
        
        // Create a new configuration with the custom prefix
        $customPrefixConfig = new Configuration([], 'CUSTOM_PREFIX_');
        
        // Check that the environment variable was loaded with the correct key
        $this->assertEquals('custom_value', $customPrefixConfig->get('test.value'));
        
        // Clean up
        putenv('CUSTOM_PREFIX_TEST_VALUE');
    }

    /**
     * Test merge method with simple values.
     */
    public function testMergeWithSimpleValues(): void
    {
        // Create initial config
        $this->config->set('test.key1', 'value1');
        $this->config->set('test.key2', 'value2');
        
        // Create values to merge
        $newValues = [
            'test' => [
                'key2' => 'new_value',
                'key3' => 'value3'
            ]
        ];
        
        // Merge values
        $result = $this->config->merge($newValues);
        
        // Test that merge is chainable
        $this->assertInstanceOf(Configuration::class, $result);
        
        // Check that values were merged correctly
        $this->assertEquals('value1', $this->config->get('test.key1')); // Unchanged
        $this->assertEquals('new_value', $this->config->get('test.key2')); // Updated
        $this->assertEquals('value3', $this->config->get('test.key3')); // Added
    }

    /**
     * Test merge with complex nested arrays.
     */
    public function testMergeWithComplexNestedArrays(): void
    {
        // Create initial config with nested arrays
        $this->config->set('parent.child.grandchild1', 'value1');
        $this->config->set('parent.child.grandchild2', ['item1', 'item2']);
        
        // Create values to merge
        $newValues = [
            'parent' => [
                'child' => [
                    'grandchild2' => ['item3', 'item4'], // Replace array
                    'grandchild3' => 'new_value' // Add new key
                ],
                'sibling' => 'sibling_value' // Add new sibling
            ]
        ];
        
        // Merge values
        $this->config->merge($newValues);
        
        // Check that values were merged correctly
        $this->assertEquals('value1', $this->config->get('parent.child.grandchild1')); // Unchanged
        $this->assertEquals(['item3', 'item4'], $this->config->get('parent.child.grandchild2')); // Replaced
        $this->assertEquals('new_value', $this->config->get('parent.child.grandchild3')); // Added
        $this->assertEquals('sibling_value', $this->config->get('parent.sibling')); // Added
    }

    /**
     * Test getProviderConfig with enabled provider.
     */
    public function testGetProviderConfigWithEnabledProvider(): void
    {
        // Create config with an enabled provider
        $this->config->set('providers.test_provider.enabled', true);
        $this->config->set('providers.test_provider.client_id', 'test_id');
        
        // Get the provider config
        $providerConfig = $this->config->getProviderConfig('test_provider');
        
        // Check that config was returned
        $this->assertIsArray($providerConfig);
        $this->assertTrue($providerConfig['enabled']);
        $this->assertEquals('test_id', $providerConfig['client_id']);
    }

    /**
     * Test getProviderConfig with disabled provider throws exception.
     */
    public function testGetProviderConfigWithDisabledProviderThrowsException(): void
    {
        // Create config with a disabled provider
        $this->config->set('providers.test_provider.enabled', false);
        
        // Expect an exception
        $this->expectException(ConfigException::class);
        $this->expectExceptionMessage('Provider test_provider is not enabled');
        
        // Try to get the provider config
        $this->config->getProviderConfig('test_provider');
    }

    /**
     * Test getProviderConfig with non-existent provider throws exception.
     */
    public function testGetProviderConfigWithNonExistentProviderThrowsException(): void
    {
        // Expect an exception
        $this->expectException(ConfigException::class);
        $this->expectExceptionMessage('Provider non_existent is not configured');
        
        // Try to get the provider config
        $this->config->getProviderConfig('non_existent');
    }

    /**
     * Test getEnabledProviders returns only enabled providers.
     */
    public function testGetEnabledProviders(): void
    {
        // Create config with multiple providers
        $this->config->set('providers.enabled_provider.enabled', true);
        $this->config->set('providers.disabled_provider.enabled', false);
        $this->config->set('providers.another_enabled.enabled', true);
        
        // Get enabled providers
        $enabledProviders = $this->config->getEnabledProviders();
        
        // Check that only enabled providers are returned
        $this->assertCount(2, $enabledProviders);
        $this->assertArrayHasKey('enabled_provider', $enabledProviders);
        $this->assertArrayHasKey('another_enabled', $enabledProviders);
        $this->assertArrayNotHasKey('disabled_provider', $enabledProviders);
    }

    /**
     * Test getting a value with an invalid type for casting.
     */
    public function testGetAsWithInvalidType(): void
    {
        $this->config->set('test.value', 'string_value');
        
        // Should return the original value for an invalid type
        $this->assertEquals('string_value', $this->config->getAs('test.value', 'invalid_type'));
    }

    /**
     * Test handling of null values in configuration.
     */
    public function testNullHandling(): void
    {
        // Set a null value
        $this->config->set('test.null', null);
        
        // Check that the value is null
        $this->assertNull($this->config->get('test.null'));
        
        // Check type conversion of null values
        $this->assertFalse($this->config->getAs('test.null', 'bool'));
        $this->assertEquals(0, $this->config->getAs('test.null', 'int'));
        $this->assertEquals(0.0, $this->config->getAs('test.null', 'float'));
        $this->assertEquals('', $this->config->getAs('test.null', 'string'));
        $this->assertEquals([], $this->config->getAs('test.null', 'array'));
    }
}