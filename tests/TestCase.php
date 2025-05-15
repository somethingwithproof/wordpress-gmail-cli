<?php

namespace WordPressGmailCli\SocialAuth\Tests;

use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use WP_Mock;

/**
 * Base test case for all our tests.
 * 
 * Handles setting up and tearing down WP_Mock.
 */
abstract class TestCase extends PHPUnitTestCase
{
    /**
     * Set up before each test.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        WP_Mock::setUp();
    }

    /**
     * Tear down after each test.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        WP_Mock::tearDown();
        parent::tearDown();
    }
}