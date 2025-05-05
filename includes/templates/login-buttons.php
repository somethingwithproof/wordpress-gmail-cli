<?php
/**
 * Social login buttons template
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 *
 * @var array $providers Array of configured providers
 */

defined('ABSPATH') || exit;

$current_url = home_url(add_query_arg(null, null));
?>

<div class="wp-social-auth-login-buttons">
    <?php foreach ($providers as $provider_id => $provider): ?>
        <?php
        $auth_url = add_query_arg([
            'action' => 'social_login',
            'provider' => $provider_id,
            'redirect_to' => urlencode($current_url),
            '_wpnonce' => wp_create_nonce('social-auth-' . $provider_id),
        ], admin_url('admin-ajax.php'));
        ?>
        <div class="wp-social-auth-button wp-social-auth-<?php echo esc_attr($provider_id); ?>">
            <a href="<?php echo esc_url($auth_url); ?>" class="button">
                <span class="wp-social-auth-icon"></span>
                <span class="wp-social-auth-text">
                    <?php echo esc_html($provider->getLabel()); ?>
                </span>
            </a>
        </div>
    <?php endforeach; ?>
</div>
