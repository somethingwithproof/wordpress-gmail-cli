<?php

namespace WordPressGmailCli\SocialAuth\Tests\Unit\Providers;

use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Token\AccessToken;
use Mockery;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use WordPressGmailCli\SocialAuth\Exception\ConfigException;
use WordPressGmailCli\SocialAuth\Exception\ProviderException;
use WordPressGmailCli\SocialAuth\Providers\GoogleProvider;

/**
 * Test case for the GoogleProvider class.
 */
class GoogleProviderTest extends TestCase
{
    /**
     * @var \Mockery\MockInterface|LoggerInterface
     */
    private $mockLogger;
    
    /**
     * @var array
     */
    private $validConfig;
    
    /**
     * @var GoogleProvider
     */
    private $googleProvider;
    
    /**
     * @var \Mockery\MockInterface|Google
     */
    private $mockOAuth2Provider;
    
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
        
        // Create a valid configuration
        $this->validConfig = [
            'client_id' => 'test_client_id',
            'client_secret' => 'test_client_secret',
            'hosted_domain' => 'example.com',
            'enabled' => true
        ];
        
        // Create a mock OAuth2 provider
        $this->mockOAuth2Provider = Mockery::mock(Google::class);
        
        // Create the GoogleProvider, but using reflection to inject the mock OAuth2 provider
        $this->googleProvider = new GoogleProvider($this->validConfig, $this->mockLogger);
        
        // Use reflection to replace the private provider property with our mock
        $reflectionClass = new \ReflectionClass($this->googleProvider);
        $reflectionProperty = $reflectionClass->getProperty('provider');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->googleProvider, $this->mockOAuth2Provider);
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
     * Test the getIdentifier method.
     */
    public function testGetIdentifier(): void
    {
        $this->assertEquals('google', $this->googleProvider->getIdentifier());
    }
    
    /**
     * Test the validateConfig method with valid configuration.
     */
    public function testValidateConfigWithValidConfig(): void
    {
        $result = $this->googleProvider->validateConfig();
        $this->assertTrue($result);
    }
    
    /**
     * Test the validateConfig method with invalid configuration.
     */
    public function testValidateConfigWithInvalidConfig(): void
    {
        // Create a provider with missing client_secret
        $invalidConfig = [
            'client_id' => 'test_client_id',
            // 'client_secret' is missing
        ];
        
        $provider = new GoogleProvider($invalidConfig, $this->mockLogger);
        
        $this->expectException(ConfigException::class);
        $provider->validateConfig();
    }
    
    /**
     * Test the isConfigured method with valid configuration.
     */
    public function testIsConfiguredWithValidConfig(): void
    {
        $result = $this->googleProvider->isConfigured();
        $this->assertTrue($result);
    }
    
    /**
     * Test the isConfigured method with invalid configuration.
     */
    public function testIsConfiguredWithInvalidConfig(): void
    {
        // Create a provider with missing client_secret
        $invalidConfig = [
            'client_id' => 'test_client_id',
            // 'client_secret' is missing
        ];
        
        $provider = new GoogleProvider($invalidConfig, $this->mockLogger);
        
        $result = $provider->isConfigured();
        $this->assertFalse($result);
    }
    
    /**
     * Test the getAuthUrl method.
     */
    public function testGetAuthUrl(): void
    {
        // Setup expectations for the mock
        $this->mockOAuth2Provider->shouldReceive('getAuthorizationUrl')
            ->once()
            ->with(Mockery::on(function($options) {
                return isset($options['scope']) &&
                    in_array('email', $options['scope']) &&
                    in_array('profile', $options['scope']) &&
                    in_array('openid', $options['scope']) &&
                    isset($options['state']) &&
                    isset($options['access_type']) &&
                    isset($options['prompt']);
            }))
            ->andReturn('https://accounts.google.com/o/oauth2/auth?test=1');
        
        $authUrl = $this->googleProvider->getAuthUrl();
        
        $this->assertStringContainsString('https://accounts.google.com/o/oauth2/auth', $authUrl);
    }
    
    /**
     * Test the getUserData method with valid data.
     */
    public function testGetUserDataWithValidData(): void
    {
        // Set the state in $_GET
        $_GET['state'] = 'valid_state';
        
        // Create test data
        $code = 'test_auth_code';
        $accessToken = Mockery::mock(AccessToken::class);
        $accessToken->shouldReceive('jsonSerialize')
            ->andReturn([
                'access_token' => 'test_access_token',
                'refresh_token' => 'test_refresh_token',
                'expires_in' => 3600,
            ]);
        
        $googleUser = Mockery::mock(GoogleUser::class);
        $googleUser->shouldReceive('getEmail')->andReturn('test@example.com');
        $googleUser->shouldReceive('getFirstName')->andReturn('Test');
        $googleUser->shouldReceive('getLastName')->andReturn('User');
        $googleUser->shouldReceive('getName')->andReturn('Test User');
        $googleUser->shouldReceive('getId')->andReturn('123456789');
        $googleUser->shouldReceive('getAvatar')->andReturn('https://example.com/avatar.jpg');
        $googleUser->shouldReceive('getVerifiedEmail')->andReturn(true);
        $googleUser->shouldReceive('getLocale')->andReturn('en-US');
        
        // Setup our provider to return a valid state
        $googleProvider = Mockery::mock(GoogleProvider::class, [$this->validConfig, $this->mockLogger])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        
        $googleProvider->shouldReceive('verifyState')
            ->with('valid_state')
            ->andReturn(true);
        
        // Replace the OAuth provider
        $reflectionClass = new \ReflectionClass($googleProvider);
        $reflectionProperty = $reflectionClass->getProperty('provider');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($googleProvider, $this->mockOAuth2Provider);
        
        // Setup the OAuth provider expectations
        $this->mockOAuth2Provider->shouldReceive('getAccessToken')
            ->once()
            ->with('authorization_code', ['code' => $code])
            ->andReturn($accessToken);
        
        $this->mockOAuth2Provider->shouldReceive('getResourceOwner')
            ->once()
            ->with($accessToken)
            ->andReturn($googleUser);
        
        // Get the user data
        $userData = $googleProvider->getUserData($code);
        
        // Assert the user data is correct
        $this->assertEquals('test@example.com', $userData['email']);
        $this->assertEquals('Test', $userData['first_name']);
        $this->assertEquals('Test User', $userData['display_name']);
        $this->assertEquals('google', $userData['provider']);
        $this->assertEquals('123456789', $userData['provider_id']);
        $this->assertEquals('test_access_token', $userData['access_token']);
        $this->assertEquals('test_refresh_token', $userData['refresh_token']);
        $this->assertEquals('en-US', $userData['locale']);
        $this->assertArrayHasKey('expires_in', $userData);
        $this->assertArrayHasKey('expires_at', $userData);
    }
    
    /**
     * Test the getUserData method with invalid state.
     */
    public function testGetUserDataWithInvalidState(): void
    {
        // Set the state in $_GET
        $_GET['state'] = 'invalid_state';
        
        // Create a provider that will fail state verification
        $googleProvider = Mockery::mock(GoogleProvider::class, [$this->validConfig, $this->mockLogger])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        
        $googleProvider->shouldReceive('verifyState')
            ->with('invalid_state')
            ->andReturn(false);
            
        // Setup logger expectation for error
        $this->mockLogger->shouldReceive('error')
            ->once()
            ->with('Invalid state parameter', Mockery::any());
            
        // Replace the original provider property
        $reflectionClass = new \ReflectionClass($googleProvider);
        $reflectionProperty = $reflectionClass->getProperty('provider');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($googleProvider, $this->mockOAuth2Provider);
        
        // Expect an exception
        $this->expectException(ProviderException::class);
        $this->expectExceptionMessage('Invalid state parameter');
        
        $googleProvider->getUserData('test_code');
    }
    
    /**
     * Test the getUserData method with missing email.
     */
    public function testGetUserDataWithMissingEmail(): void
    {
        // Set the state in $_GET
        $_GET['state'] = 'valid_state';
        
        // Create test data
        $code = 'test_auth_code';
        $accessToken = Mockery::mock(AccessToken::class);
        $accessToken->shouldReceive('jsonSerialize')
            ->andReturn(['access_token' => 'test_access_token']);
        
        $googleUser = Mockery::mock(GoogleUser::class);
        $googleUser->shouldReceive('getEmail')->andReturn(''); // Missing email
        $googleUser->shouldReceive('getId')->andReturn('123456789');
        
        // Setup our provider to return a valid state
        $googleProvider = Mockery::mock(GoogleProvider::class, [$this->validConfig, $this->mockLogger])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        
        $googleProvider->shouldReceive('verifyState')
            ->with('valid_state')
            ->andReturn(true);
        
        // Replace the OAuth provider
        $reflectionClass = new \ReflectionClass($googleProvider);
        $reflectionProperty = $reflectionClass->getProperty('provider');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($googleProvider, $this->mockOAuth2Provider);
        
        // Setup the OAuth provider expectations
        $this->mockOAuth2Provider->shouldReceive('getAccessToken')
            ->once()
            ->with('authorization_code', ['code' => $code])
            ->andReturn($accessToken);
        
        $this->mockOAuth2Provider->shouldReceive('getResourceOwner')
            ->once()
            ->with($accessToken)
            ->andReturn($googleUser);
            
        // Setup logger expectation for warning
        $this->mockLogger->shouldReceive('warning')
            ->once()
            ->with('Google account email missing', Mockery::any());
        
        // Expect an exception
        $this->expectException(ProviderException::class);
        $this->expectExceptionMessage('Google account email missing');
        
        $googleProvider->getUserData($code);
    }
    
    /**
     * Test the getUserData method with unverified email.
     */
    public function testGetUserDataWithUnverifiedEmail(): void
    {
        // Set the state in $_GET
        $_GET['state'] = 'valid_state';
        
        // Create test data
        $code = 'test_auth_code';
        $accessToken = Mockery::mock(AccessToken::class);
        $accessToken->shouldReceive('jsonSerialize')
            ->andReturn(['access_token' => 'test_access_token']);
        
        $googleUser = Mockery::mock(GoogleUser::class);
        $googleUser->shouldReceive('getEmail')->andReturn('test@example.com');
        $googleUser->shouldReceive('getVerifiedEmail')->andReturn(false); // Unverified email
        $googleUser->shouldReceive('getId')->andReturn('123456789');
        
        // Setup our provider to return a valid state
        $googleProvider = Mockery::mock(GoogleProvider::class, [$this->validConfig, $this->mockLogger])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        
        $googleProvider->shouldReceive('verifyState')
            ->with('valid_state')
            ->andReturn(true);
        
        // Replace the OAuth provider
        $reflectionClass = new \ReflectionClass($googleProvider);
        $reflectionProperty = $reflectionClass->getProperty('provider');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($googleProvider, $this->mockOAuth2Provider);
        
        // Setup the OAuth provider expectations
        $this->mockOAuth2Provider->shouldReceive('getAccessToken')
            ->once()
            ->with('authorization_code', ['code' => $code])
            ->andReturn($accessToken);
        
        $this->mockOAuth2Provider->shouldReceive('getResourceOwner')
            ->once()
            ->with($accessToken)
            ->andReturn($googleUser);
            
        // Setup logger expectation for warning
        $this->mockLogger->shouldReceive('warning')
            ->once()
            ->with('Google account email not verified', Mockery::any());
        
        // Expect an exception
        $this->expectException(ProviderException::class);
        $this->expectExceptionMessage('Google account email not verified');
        
        $googleProvider->getUserData($code);
    }
    
    /**
     * Test handling of OAuth2 provider exceptions.
     */
    public function testHandlingOfOAuth2ProviderExceptions(): void
    {
        // Set the state in $_GET
        $_GET['state'] = 'valid_state';
        
        // Setup our provider to return a valid state
        $googleProvider = Mockery::mock(GoogleProvider::class, [$this->validConfig, $this->mockLogger])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        
        $googleProvider->shouldReceive('verifyState')
            ->with('valid_state')
            ->andReturn(true);
        
        // Replace the OAuth provider
        $reflectionClass = new \ReflectionClass($googleProvider);
        $reflectionProperty = $reflectionClass->getProperty('provider');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($googleProvider, $this->mockOAuth2Provider);
        
        // Setup the OAuth provider to throw an exception
        $oauthException = new \League\OAuth2\Client\Provider\Exception\IdentityProviderException(
            'Invalid client credentials',
            401,
            '{"error":"invalid_client","error_description":"Invalid client credentials"}'
        );
        
        $this->mockOAuth2Provider->shouldReceive('getAccessToken')
            ->once()
            ->with('authorization_code', ['code' => 'test_code'])
            ->andThrow($oauthException);
            
        // Setup logger expectation for error
        $this->mockLogger->shouldReceive('error')
            ->once()
            ->with('Google OAuth error', Mockery::any());
        
        // Expect our provider exception
        $this->expectException(ProviderException::class);
        $this->expectExceptionMessage('Google OAuth error: Invalid client credentials');
        
        $googleProvider->getUserData('test_code');
    }
}