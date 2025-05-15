<?php

namespace WordPressGmailCli\SocialAuth\Tests\Functional;

use WP_Mock;
use WordPressGmailCli\SocialAuth\Authentication\AuthenticationManager;
use WordPressGmailCli\SocialAuth\Providers\GoogleProvider;
use WordPressGmailCli\SocialAuth\Providers\ProviderFactory;

/**
 * Test the complete authentication flow.
 */
class AuthenticationFlowTest extends TestCase
{
    /**
     * Test the complete Google authentication flow.
     */
    public function testGoogleAuthenticationFlow(): void
    {
        // Mock configuration
        $config = [
            'providers' => [
                'google' => [
                    'enabled' => true,
                    'client_id' => 'test-client-id',
                    'client_secret' => 'test-client-secret',
                    'redirect_uri' => 'https://example.com/wp-login.php?action=social_auth&provider=google',
                ],
            ],
        ];

        // Mock the WordPress option to return our test config
        WP_Mock::userFunction('get_option')
            ->with('wp_social_auth_settings', WP_Mock\Functions::type('array'))
            ->andReturn($config);
        
        // Mock nonce verification
        WP_Mock::userFunction('wp_create_nonce')->andReturn('test-nonce');
        WP_Mock::userFunction('wp_verify_nonce')->andReturn(true);
        
        // Mock HTTP request data
        $_GET['action'] = 'social_auth';
        $_GET['provider'] = 'google';
        $_GET['_wpnonce'] = 'test-nonce';
        
        // Initialize the plugin
        $this->plugin->register();
        
        // Get authentication manager using reflection
        $reflectionClass = new \ReflectionClass(get_class($this->plugin));
        $authManagerProperty = $reflectionClass->getProperty('authenticationManager');
        $authManagerProperty->setAccessible(true);
        $authManager = $authManagerProperty->getValue($this->plugin);
        
        // Test that authentication manager was created
        $this->assertInstanceOf(AuthenticationManager::class, $authManager);
        
        // Get provider factory
        $providerFactoryProperty = $reflectionClass->getProperty('providerFactory');
        $providerFactoryProperty->setAccessible(true);
        $providerFactory = $providerFactoryProperty->getValue($this->plugin);
        
        // Test that provider factory was created
        $this->assertInstanceOf(ProviderFactory::class, $providerFactory);
        
        // Test that Google provider can be created
        WP_Mock::userFunction('site_url')->andReturn('https://example.com');
        $googleProvider = $providerFactory->createProvider('google');
        $this->assertInstanceOf(GoogleProvider::class, $googleProvider);
        
        // Test the authorization URL generation
        $authUrl = $googleProvider->getAuthorizationUrl();
        $this->assertStringContainsString('accounts.google.com', $authUrl);
        $this->assertStringContainsString('client_id=test-client-id', $authUrl);
        
        // Simulate the OAuth callback
        $_GET['code'] = 'test-auth-code';
        $_GET['state'] = 'test-state';
        
        // Mock token exchange
        WP_Mock::userFunction('wp_remote_post')->andReturn([
            'body' => json_encode([
                'access_token' => 'test-access-token',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => 'test-refresh-token',
            ]),
            'response' => [
                'code' => 200,
            ],
        ]);
        
        // Mock resource owner details request
        WP_Mock::userFunction('wp_remote_get')->andReturn([
            'body' => json_encode([
                'id' => '12345',
                'email' => 'test@example.com',
                'name' => 'Test User',
                'picture' => 'https://example.com/avatar.jpg',
            ]),
            'response' => [
                'code' => 200,
            ],
        ]);
        
        // Mock WordPress user functions
        WP_Mock::userFunction('email_exists')->with('test@example.com')->andReturn(false);
        WP_Mock::userFunction('username_exists')->andReturn(false);
        WP_Mock::userFunction('wp_generate_password')->andReturn('random-password');
        WP_Mock::userFunction('wp_insert_user')->andReturn(123);
        WP_Mock::userFunction('update_user_meta')->andReturn(true);
        WP_Mock::userFunction('wp_signon')->andReturn((object) [
            'ID' => 123,
            'user_login' => 'test_user',
        ]);
        WP_Mock::userFunction('wp_safe_redirect')->andReturn(true);
        
        // Execute authentication (this would typically be called by WordPress)
        $authManager->handleAuthentication('google');
        
        // Verify all expectations were met
        $this->assertConditionsMet();
    }
}