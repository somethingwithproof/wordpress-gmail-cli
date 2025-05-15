<?php

namespace WordPressGmailCli\SocialAuth\Tests\Integration;

use WordPressGmailCli\SocialAuth\Tests\TestCase as BaseTestCase;

/**
 * Base TestCase for integration tests.
 * 
 * Integration tests test the interaction between multiple components.
 */
abstract class TestCase extends BaseTestCase
{
    /**
     * Set up for integration tests
     * 
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Set up common mocks and expectations for integration tests
        $this->setupCommonWordPressMocks();
    }
    
    /**
     * Set up common WordPress mocks that are needed for most integration tests
     * 
     * @return void
     */
    protected function setupCommonWordPressMocks(): void
    {
        // Mock WordPress hooks
        \WP_Mock::userFunction('add_action')->andReturn(true);
        \WP_Mock::userFunction('add_filter')->andReturn(true);
        \WP_Mock::userFunction('do_action')->andReturn(null);
        \WP_Mock::userFunction('apply_filters')->andReturnFirstArg();
        
        // Mock WordPress options API
        \WP_Mock::userFunction('get_option')->andReturnUsing(function($option, $default = false) {
            static $options = [];
            return $options[$option] ?? $default;
        });
        
        \WP_Mock::userFunction('update_option')->andReturnUsing(function($option, $value) {
            static $options = [];
            $options[$option] = $value;
            return true;
        });
        
        // Mock WordPress escaping functions
        \WP_Mock::userFunction('esc_html')->andReturnFirstArg();
        \WP_Mock::userFunction('esc_url')->andReturnFirstArg();
        \WP_Mock::userFunction('esc_attr')->andReturnFirstArg();
        \WP_Mock::userFunction('sanitize_text_field')->andReturnFirstArg();
    }
}