<?php

namespace WordPressGmailCli\SocialAuth;

/**
 * Factory class to create and initialize the SocialAuth plugin.
 */
class SocialAuthFactory
{
    /**
     * Create and initialize the SocialAuth instance.
     *
     * @param array $config Optional config override.
     * @return SocialAuth The social authentication instance.
     */
    public static function create(array $config = []): SocialAuth
    {
        // Get settings from options if not provided via config array.
        if (empty($config)) {
            $config = [
                'google_client_id'     => get_option('wp_social_auth_google_client_id'),
                'google_client_secret' => get_option('wp_social_auth_google_client_secret'),
                'facebook_app_id'      => get_option('wp_social_auth_facebook_app_id'),
                'facebook_app_secret'  => get_option('wp_social_auth_facebook_app_secret'),
            ];
        }

        // Initialize the plugin class.
        return new SocialAuth($config);
    }
}