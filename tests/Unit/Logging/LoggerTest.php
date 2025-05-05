<?php

namespace WordPressGmailCli\SocialAuth\Tests\Unit\Logging;

use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use WordPressGmailCli\SocialAuth\Logging\Logger;

/**
 * Test case for the Logger class.
 */
class LoggerTest extends TestCase
{
    /**
     * @var Logger
     */
    private Logger $logger;
    
    /**
     * @var array
     */
    private array $loggedMessages = [];
    
    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Create a fresh logger instance for each test
        $this->logger = new Logger('test-logger', LogLevel::DEBUG);
        
        // Clear logged messages array
        $this->loggedMessages = [];
    }
    
    /**
     * Test constructor with custom values.
     */
    public function testConstructor(): void
    {
        $logger = new Logger('custom-logger', LogLevel::WARNING);
        
        $this->assertEquals('custom-logger', $logger->getIdentifier());
        $this->assertEquals(LogLevel::WARNING, $logger->getMinimumLevel());
    }
    
    /**
     * Test constructor with WP_DEBUG enabled.
     */
    public function testConstructorWithWpDebugEnabled(): void
    {
        // Define WP_DEBUG as true
        define('WP_DEBUG', true);
        
        $logger = new Logger('debug-logger', LogLevel::INFO);
        
        $this->assertEquals(LogLevel::DEBUG, $logger->getMinimumLevel());
    }
    
    /**
     * Test the setIdentifier method.
     */
    public function testSetIdentifier(): void
    {
        $result = $this->logger->setIdentifier('new-identifier');
        
        $this->assertInstanceOf(Logger::class, $result);
        $this->assertEquals('new-identifier', $this->logger->getIdentifier());
    }
    
    /**
     * Test the setMinimumLevel method with valid level.
     */
    public function testSetMinimumLevelWithValidLevel(): void
    {
        $result = $this->logger->setMinimumLevel(LogLevel::WARNING);
        
        $this->assertInstanceOf(Logger::class, $result);
        $this->assertEquals(LogLevel::WARNING, $this->logger->getMinimumLevel());
    }
    
    /**
     * Test the setMinimumLevel method with invalid level.
     */
    public function testSetMinimumLevelWithInvalidLevel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->logger->setMinimumLevel('invalid_level');
    }
    
    /**
     * Test logger methods with levels above minimum level.
     */
    public function testLoggingAboveMinimumLevel(): void
    {
        // Set minimum level to WARNING
        $this->logger->setMinimumLevel(LogLevel::WARNING);
        
        // Set up error_log capture
        $this->startCaptureErrorLog();
        
        // Test log methods
        $this->logger->emergency('Emergency message', ['key' => 'value']);
        $this->logger->alert('Alert message');
        $this->logger->critical('Critical message');
        $this->logger->error('Error message');
        $this->logger->warning('Warning message');
        
        // Check that messages were logged
        $logs = $this->getLoggedMessages();
        $this->assertCount(5, $logs);
        $this->assertStringContainsString('EMERGENCY', $logs[0]);
        $this->assertStringContainsString('Emergency message', $logs[0]);
        $this->assertStringContainsString('key', $logs[0]);
        $this->assertStringContainsString('ALERT', $logs[1]);
        $this->assertStringContainsString('Alert message', $logs[1]);
        $this->assertStringContainsString('CRITICAL', $logs[2]);
        $this->assertStringContainsString('Critical message', $logs[2]);
        $this->assertStringContainsString('ERROR', $logs[3]);
        $this->assertStringContainsString('Error message', $logs[3]);
        $this->assertStringContainsString('WARNING', $logs[4]);
        $this->assertStringContainsString('Warning message', $logs[4]);
    }
    
    /**
     * Test logger methods with levels below minimum level.
     */
    public function testLoggingBelowMinimumLevel(): void
    {
        // Set minimum level to WARNING
        $this->logger->setMinimumLevel(LogLevel::WARNING);
        
        // Set up error_log capture
        $this->startCaptureErrorLog();
        
        // Test log methods
        $this->logger->notice('Notice message');
        $this->logger->info('Info message');
        $this->logger->debug('Debug message');
        
        // Check that messages were not logged
        $logs = $this->getLoggedMessages();
        $this->assertCount(0, $logs);
    }
    
    /**
     * Test error log messages are always logged regardless of minimum level.
     */
    public function testErrorsAlwaysLogged(): void
    {
        // Set minimum level to INFO
        $this->logger->setMinimumLevel(LogLevel::INFO);
        
        // Set up error_log capture
        $this->startCaptureErrorLog();
        
        // Test error log
        $this->logger->error('Critical error message');
        
        // Check that error was logged
        $logs = $this->getLoggedMessages();
        $this->assertCount(1, $logs);
        $this->assertStringContainsString('ERROR', $logs[0]);
        $this->assertStringContainsString('Critical error message', $logs[0]);
    }
    
    /**
     * Test log message interpolation.
     */
    public function testLogMessageInterpolation(): void
    {
        // Set up error_log capture
        $this->startCaptureErrorLog();
        
        // Test log with placeholders
        $this->logger->error('User {user_id} attempted action {action}', [
            'user_id' => 123,
            'action' => 'login',
            'extra' => 'data',
        ]);
        
        // Check that placeholders were replaced
        $logs = $this->getLoggedMessages();
        $this->assertCount(1, $logs);
        $this->assertStringContainsString('User 123 attempted action login', $logs[0]);
        $this->assertStringContainsString('"extra": "data"', $logs[0]);
    }
    
    /**
     * Test sensitive data redaction in logs.
     */
    public function testSensitiveDataRedaction(): void
    {
        // Set up error_log capture
        $this->startCaptureErrorLog();
        
        // Test log with sensitive data
        $this->logger->info('Authentication attempt', [
            'username' => 'test_user',
            'password' => 'secret123',
            'access_token' => 'abc123xyz',
            'client_secret' => 'client_secret_value',
            'nested' => [
                'api_key' => 'nested_api_key',
                'safe' => 'safe_value',
            ],
        ]);
        
        // Check that sensitive data was redacted
        $logs = $this->getLoggedMessages();
        $this->assertCount(1, $logs);
        $this->assertStringContainsString('"username": "test_user"', $logs[0]);
        $this->assertStringContainsString('"password": "***REDACTED***"', $logs[0]);
        $this->assertStringContainsString('"access_token": "***REDACTED***"', $logs[0]);
        $this->assertStringContainsString('"client_secret": "***REDACTED***"', $logs[0]);
        $this->assertStringContainsString('"api_key": "***REDACTED***"', $logs[0]);
        $this->assertStringContainsString('"safe": "safe_value"', $logs[0]);
    }
    
    /**
     * Test logging with different WP_DEBUG_LOG values.
     */
    public function testLoggingWithDifferentWpDebugLogValues(): void
    {
        // Test with WP_DEBUG_LOG as true
        define('WP_DEBUG_LOG', true);
        
        // Set up error_log capture
        $this->startCaptureErrorLog();
        
        // Log a message
        $this->logger->info('Test with WP_DEBUG_LOG true');
        
        // Check that message was logged
        $logs = $this->getLoggedMessages();
        $this->assertCount(1, $logs);
        
        // Clean up
        $this->loggedMessages = [];
    }
    
    /**
     * Helper method to start capturing error_log output.
     */
    private function startCaptureErrorLog(): void
    {
        // Override the error_log function
        global $test_error_log_function;
        $test_error_log_function = function($message) {
            $this->loggedMessages[] = $message;
        };
    }
    
    /**
     * Helper method to get logged messages.
     *
     * @return array
     */
    private function getLoggedMessages(): array
    {
        return $this->loggedMessages;
    }
}

// Mock error_log function if not running in WordPress
if (!function_exists('error_log')) {
    function error_log($message, $message_type = 0, $destination = null, $headers = null) {
        global $test_error_log_function;
        if (isset($test_error_log_function) && is_callable($test_error_log_function)) {
            call_user_func($test_error_log_function, $message);
        }
    }
}

// Mock wp_json_encode function if not defined
if (!function_exists('wp_json_encode')) {
    function wp_json_encode($data, $options = 0, $depth = 512) {
        return json_encode($data, $options, $depth);
    }
}