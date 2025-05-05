<?php

namespace WordPressGmailCli\SocialAuth\Tests\Unit\Providers;

use Mockery;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use WordPressGmailCli\SocialAuth\Exception\ConfigException;
use WordPressGmailCli\SocialAuth\Exception\ProviderException;
use WordPressGmailCli\SocialAuth\Providers\AbstractProvider;

/**
 * Test case for the AbstractProvider class.
 */
class AbstractProviderTest extends TestCase
{
    /**
     * @var \Mockery\MockInterface|LoggerInterface
     */
    private $mockLogger;
    
    /**
     * @var \Mockery\MockInterface|AbstractProvider
     */
    private $provider;
    
    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Create a mock logger
        $this->mockLogger = Mockery::mock(LoggerInterface::class);
        $this->mockLogger->shouldReceive('debug')->byDefault();
        $this->mockLogger->shouldReceive('info')->byDefault();
        $this->mockLogger->shouldReceive('warning')->byDefault();
        $this->mockLogger->shouldReceive('error')->byDefault();
        
        // Create a mock of the AbstractProvider
        $this->provider = Mockery::mock(AbstractProvider::class, [
            [
                'client_id' => 'test_client_id',
                'client_secret' => 'test_client_secret',
            ],
            $this->mockLogger,
        ])->makePartial();
        
        // Mock methods that must be implemented by child classes
        $this->provider->shouldReceive('getIdentifier')->andReturn('test');
        $this->provider->shouldReceive('getAuthUrl')->andReturn('https://example.com/auth');
        $this->provider->shouldReceive('getUserData')->andReturn(['email' => 'test@example.com']);
        $this->provider->shouldReceive('getRequiredConfigKeys')->andReturn(['client_id', 'client_secret']);
    }
    
    /**
     * Clean up after tests.
     */
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
    
    /**
     * Test the validateConfig method with valid configuration.
     */
    public function testValidateConfigWithValidConfig(): void
    {
        $result = $this->provider->validateConfig();
        $this->assertTrue($result);
    }
    
    /**
     * Test the validateConfig method with invalid configuration.
     */
    public function testValidateConfigWithInvalidConfig(): void
    {
        // Create a provider with missing client_secret
        $provider = Mockery::mock(AbstractProvider::class, [
            [
                'client_id' => 'test_client_id',
                // 'client_secret' is missing
            ],
            $this->mockLogger,
        ])->makePartial();
        
        $provider->shouldReceive('getIdentifier')->andReturn('test');
        $provider->shouldReceive('getRequiredConfigKeys')->andReturn(['client_id', 'client_secret']);
        
        $this->expectException(ConfigException::class);
        $provider->validateConfig();
    }
    
    /**
     * Test the isConfigured method with valid configuration.
     */
    public function testIsConfiguredWithValidConfig(): void
    {
        $result = $this->provider->isConfigured();
        $this->assertTrue($result);
    }
    
    /**
     * Test the isConfigured method with invalid configuration.
     */
    public function testIsConfiguredWithInvalidConfig(): void
    {
        // Create a provider with missing client_secret
        $provider = Mockery::mock(AbstractProvider::class, [
            [
                'client_id' => 'test_client_id',
                // 'client_secret' is missing
            ],
            $this->mockLogger,
        ])->makePartial();
        
        $provider->shouldReceive('getIdentifier')->andReturn('test');
        $provider->shouldReceive('getRequiredConfigKeys')->andReturn(['client_id', 'client_secret']);
        
        $result = $provider->isConfigured();
        $this->assertFalse($result);
    }
    
    /**
     * Test the generateState method.
     */
    public function testGenerateState(): void
    {
        // Use reflection to access protected method
        $reflectionClass = new \ReflectionClass($this->provider);
        $method = $reflectionClass->getMethod('generateState');
        $method->setAccessible(true);
        
        $state = $method->invoke($this->provider);
        
        $this->assertIsString($state);
        $this->assertEquals(32, strlen($state));
    }
    
    /**
     * Test the verifyState method with valid state.
     */
    public function testVerifyStateWithValidState(): void
    {
        // Use reflection to access protected method
        $reflectionClass = new \ReflectionClass($this->provider);
        $generateMethod = $reflectionClass->getMethod('generateState');
        $generateMethod->setAccessible(true);
        
        // Generate a state
        $state = $generateMethod->invoke($this->provider);
        
        // Set up the transient mock
        global $test_options; // Reference the test options array from the mock functions
        $test_options = [];
        $transientKey = 'wp_social_auth_state_' . md5($state);
        $test_options['_transient_' . $transientKey] = time(); // Set the transient to the current time
        
        // Use reflection to access the verifyState method
        $verifyMethod = $reflectionClass->getMethod('verifyState');
        $verifyMethod->setAccessible(true);
        
        // Test verification
        $result = $verifyMethod->invoke($this->provider, $state);
        
        $this->assertTrue($result);
    }
    
    /**
     * Test the verifyState method with expired state.
     */
    public function testVerifyStateWithExpiredState(): void
    {
        // Use reflection to access protected methods
        $reflectionClass = new \ReflectionClass($this->provider);
        $generateMethod = $reflectionClass->getMethod('generateState');
        $generateMethod->setAccessible(true);
        
        // Generate a state
        $state = $generateMethod->invoke($this->provider);
        
        // Set up the transient mock with an expired timestamp (6 minutes ago)
        global $test_options; // Reference the test options array from the mock functions
        $test_options = [];
        $transientKey = 'wp_social_auth_state_' . md5($state);
        $test_options['_transient_' . $transientKey] = time() - (6 * 60); // 6 minutes ago
        
        // Expect a warning log for expired state
        $this->mockLogger->shouldReceive('warning')
            ->once()
            ->with('Expired state parameter', Mockery::any());
        
        // Use reflection to access the verifyState method
        $verifyMethod = $reflectionClass->getMethod('verifyState');
        $verifyMethod->setAccessible(true);
        
        // Test verification
        $result = $verifyMethod->invoke($this->provider, $state);
        
        $this->assertFalse($result);
    }
    
    /**
     * Test the verifyState method with invalid state.
     */
    public function testVerifyStateWithInvalidState(): void
    {
        // Set up the transient mock with no state stored
        global $test_options; // Reference the test options array from the mock functions
        $test_options = [];
        
        // Expect a warning log for invalid state
        $this->mockLogger->shouldReceive('warning')
            ->once()
            ->with('Invalid state parameter', Mockery::any());
        
        // Use reflection to access the verifyState method
        $reflectionClass = new \ReflectionClass($this->provider);
        $verifyMethod = $reflectionClass->getMethod('verifyState');
        $verifyMethod->setAccessible(true);
        
        // Test verification with invalid state
        $result = $verifyMethod->invoke($this->provider, 'invalid_state');
        
        $this->assertFalse($result);
    }
    
    /**
     * Test the makeRequest method with successful response.
     */
    public function testMakeRequestWithSuccessfulResponse(): void
    {
        // Mock the wp_remote_request function
        global $response; // Define a global variable to hold the response
        
        $response = [
            'response' => ['code' => 200],
            'body' => '{"key": "value"}',
        ];
        
        // Use reflection to access the protected makeRequest method
        $reflectionClass = new \ReflectionClass($this->provider);
        $method = $reflectionClass->getMethod('makeRequest');
        $method->setAccessible(true);
        
        // Test the method
        $result = $method->invoke($this->provider, 'https://example.com/api');
        
        $this->assertIsArray($result);
        $this->assertEquals(['key' => 'value'], $result);
    }
    
    /**
     * Test the makeRequest method with WP_Error response.
     */
    public function testMakeRequestWithWpError(): void
    {
        // Mock the wp_remote_request function to return a WP_Error
        global $response; // Define a global variable to hold the response
        
        $response = new \WP_Error('http_request_failed', 'Connection failed');
        
        // Expect an error log
        $this->mockLogger->shouldReceive('error')
            ->once()
            ->with('Provider request failed', Mockery::any());
        
        // Use reflection to access the protected makeRequest method
        $reflectionClass = new \ReflectionClass($this->provider);
        $method = $reflectionClass->getMethod('makeRequest');
        $method->setAccessible(true);
        
        // Expect an exception
        $this->expectException(ProviderException::class);
        $this->expectExceptionMessage('Failed to communicate with provider');
        
        // Test the method
        $method->invoke($this->provider, 'https://example.com/api');
    }
    
    /**
     * Test the makeRequest method with error status code.
     */
    public function testMakeRequestWithErrorStatus(): void
    {
        // Mock the wp_remote_request function to return an error status
        global $response; // Define a global variable to hold the response
        
        $response = [
            'response' => ['code' => 401],
            'body' => '{"error": "Unauthorized"}',
        ];
        
        // Expect an error log
        $this->mockLogger->shouldReceive('error')
            ->once()
            ->with('Provider returned error status', Mockery::any());
        
        // Use reflection to access the protected makeRequest method
        $reflectionClass = new \ReflectionClass($this->provider);
        $method = $reflectionClass->getMethod('makeRequest');
        $method->setAccessible(true);
        
        // Expect an exception
        $this->expectException(ProviderException::class);
        $this->expectExceptionMessage('Provider returned error status: 401');
        
        // Test the method
        $method->invoke($this->provider, 'https://example.com/api');
    }
    
    /**
     * Test the makeRequest method with invalid JSON response.
     */
    public function testMakeRequestWithInvalidJson(): void
    {
        // Mock the wp_remote_request function to return invalid JSON
        global $response; // Define a global variable to hold the response
        
        $response = [
            'response' => ['code' => 200],
            'body' => 'not valid json',
        ];
        
        // Expect an error log
        $this->mockLogger->shouldReceive('error')
            ->once()
            ->with('Invalid JSON response from provider', Mockery::any());
        
        // Use reflection to access the protected makeRequest method
        $reflectionClass = new \ReflectionClass($this->provider);
        $method = $reflectionClass->getMethod('makeRequest');
        $method->setAccessible(true);
        
        // Expect an exception
        $this->expectException(ProviderException::class);
        $this->expectExceptionMessage('Invalid response from provider');
        
        // Test the method
        $method->invoke($this->provider, 'https://example.com/api');
    }
}

// Mock WordPress functions required for testing
if (!function_exists('wp_remote_request')) {
    function wp_remote_request($url, $args = []) {
        global $response;
        return $response ?? ['response' => ['code' => 200], 'body' => '{"success": true}'];
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error($thing) {
        return is_object($thing) && get_class($thing) === 'WP_Error';
    }
}

if (!function_exists('wp_remote_retrieve_response_code')) {
    function wp_remote_retrieve_response_code($response) {
        return $response['response']['code'] ?? 200;
    }
}

if (!function_exists('wp_remote_retrieve_body')) {
    function wp_remote_retrieve_body($response) {
        return $response['body'] ?? '';
    }
}

// Mock WP_Error class if not defined
if (!class_exists('WP_Error')) {
    class WP_Error {
        private $code;
        private $message;
        
        public function __construct($code, $message) {
            $this->code = $code;
            $this->message = $message;
        }
        
        public function get_error_message() {
            return $this->message;
        }
    }
}