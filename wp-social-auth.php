<?php

namespace WordPressGmailCli\SocialAuth;

// Import the classes needed
require_once __DIR__ . '/SocialAuth.php';
require_once __DIR__ . '/SocialAuthFactory.php';

/**
 * Initializes the SocialAuth plugin.
 * Retrieves settings from options and instantiates the main class.
 *
 * @return void
 */
function initSocialAuth(): void
{
    SocialAuthFactory::create();
}

// Hook the initialization function to WordPress 'plugins_loaded' action.
add_action('plugins_loaded', __NAMESPACE__ . '\\initSocialAuth');