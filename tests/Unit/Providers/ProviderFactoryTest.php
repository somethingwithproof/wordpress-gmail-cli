<?php

namespace WordPressGmailCli\SocialAuth\Tests\Unit\Providers;

use Mockery;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use WordPressGmailCli\SocialAuth\Configuration\Configuration;
use WordPressGmailCli\SocialAuth\Exception\ProviderException;
use WordPressGmailCli\SocialAuth\Providers\GoogleProvider;
use WordPressGmailCli\SocialAuth\Providers\ProviderFactory;
use WordPressGmailCli\SocialAuth\Providers\ProviderInterface;

/**
 * Test case for the ProviderFactory class.
 */
class ProviderFactoryTest extends TestCase
{
    /**
     * @var \Mockery\MockInterface|LoggerInterface
     */
    private $mockLogger;
    
    /**
     * @var \Mockery\MockInterface|Configuration
     */
    private $mockConfig;
    
    /**
     * @var ProviderFactory
     */
    private $factory;
    
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
        
        // Create a mock configuration
        $this->mockConfig = Mockery::mock(Configuration::class);
        
        // Create the provider factory
        $this->factory = new ProviderFactory($this->mockLogger);
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
     * Test creating a provider by its identifier.
     */
    public function testCreateProvider(): void
    {
        // Setup config expectations
        $this->mockConfig->shouldReceive('getProviderConfig')
            ->with('google')
            ->andReturn([
                'client_id' => 'test_client_id',
                'client_secret' => 'test_client_secret',
                'enabled' => true,
            ]);
        
        // Create a Google provider
        $provider = $this->factory->createProvider('google', $this->mockConfig);
        
        $this->assertInstanceOf(GoogleProvider::class, $provider);
        $this->assertEquals('google', $provider->getIdentifier());
    }
    
    /**
     * Test creating a provider with an unknown identifier.
     */
    public function testCreateProviderWithUnknownIdentifier(): void
    {
        // Setup config expectations
        $this->mockConfig->shouldReceive('getProviderConfig')
            ->with('unknown')
            ->andThrow(new \Exception('Unknown provider'));
        
        // Expect a log error
        $this->mockLogger->shouldReceive('error')
            ->once()
            ->with('Failed to create provider', Mockery::any());
        
        // Expect exception
        $this->expectException(ProviderException::class);
        
        // Try to create an unknown provider
        $this->factory->createProvider('unknown', $this->mockConfig);
    }
    
    /**
     * Test getting all available providers.
     */
    public function testGetAvailableProviders(): void
    {
        $providers = $this->factory->getAvailableProviders();
        
        // We should at least have the Google provider
        $this->assertIsArray($providers);
        $this->assertArrayHasKey('google', $providers);
        $this->assertEquals('Google', $providers['google']);
    }
    
    /**
     * Test getting all configured providers.
     */
    public function testGetConfiguredProviders(): void
    {
        // Setup config expectations
        $this->mockConfig->shouldReceive('getEnabledProviders')
            ->andReturn([
                'google' => [
                    'client_id' => 'test_client_id',
                    'client_secret' => 'test_client_secret',
                    'enabled' => true,
                ],
            ]);
        
        // Create a Google provider mock
        $mockProvider = Mockery::mock(ProviderInterface::class);
        $mockProvider->shouldReceive('getIdentifier')->andReturn('google');
        $mockProvider->shouldReceive('isConfigured')->andReturn(true);
        
        // Modify the factory to use our mock provider
        $factoryMock = Mockery::mock(ProviderFactory::class, [$this->mockLogger])
            ->makePartial();
        
        $factoryMock->shouldReceive('createProvider')
            ->with('google', $this->mockConfig)
            ->andReturn($mockProvider);
        
        // Get configured providers
        $providers = $factoryMock->getConfiguredProviders($this->mockConfig);
        
        $this->assertIsArray($providers);
        $this->assertCount(1, $providers);
        $this->assertArrayHasKey('google', $providers);
        $this->assertSame($mockProvider, $providers['google']);
    }
    
    /**
     * Test getting configured providers with none configured properly.
     */
    public function testGetConfiguredProvidersWithNoneConfigured(): void
    {
        // Setup config expectations
        $this->mockConfig->shouldReceive('getEnabledProviders')
            ->andReturn([
                'google' => [
                    'client_id' => 'test_client_id',
                    'client_secret' => 'test_client_secret',
                    'enabled' => true,
                ],
            ]);
        
        // Create a Google provider mock that is not configured
        $mockProvider = Mockery::mock(ProviderInterface::class);
        $mockProvider->shouldReceive('getIdentifier')->andReturn('google');
        $mockProvider->shouldReceive('isConfigured')->andReturn(false);
        
        // Modify the factory to use our mock provider
        $factoryMock = Mockery::mock(ProviderFactory::class, [$this->mockLogger])
            ->makePartial();
        
        $factoryMock->shouldReceive('createProvider')
            ->with('google', $this->mockConfig)
            ->andReturn($mockProvider);
        
        // Get configured providers - should be empty
        $providers = $factoryMock->getConfiguredProviders($this->mockConfig);
        
        $this->assertIsArray($providers);
        $this->assertEmpty($providers);
    }
    
    /**
     * Test getting a provider instance by identifier.
     */
    public function testGetProviderInstance(): void
    {
        // Setup config expectations
        $this->mockConfig->shouldReceive('getProviderConfig')
            ->with('google')
            ->andReturn([
                'client_id' => 'test_client_id',
                'client_secret' => 'test_client_secret',
                'enabled' => true,
            ]);
        
        // Get a provider instance
        $provider = $this->factory->getProviderInstance('google', $this->mockConfig);
        
        $this->assertInstanceOf(GoogleProvider::class, $provider);
        $this->assertEquals('google', $provider->getIdentifier());
    }
    
    /**
     * Test getting a provider instance with an unknown identifier.
     */
    public function testGetProviderInstanceWithUnknownIdentifier(): void
    {
        // Setup config expectations
        $this->mockConfig->shouldReceive('getProviderConfig')
            ->with('unknown')
            ->andThrow(new \Exception('Unknown provider'));
        
        // Expect a log error
        $this->mockLogger->shouldReceive('error')
            ->once()
            ->with('Failed to create provider', Mockery::any());
        
        // Expect null return
        $provider = $this->factory->getProviderInstance('unknown', $this->mockConfig);
        $this->assertNull($provider);
    }
}