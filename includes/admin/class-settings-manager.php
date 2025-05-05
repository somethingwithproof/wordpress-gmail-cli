<?php
/**
 * Settings Manager
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */

namespace WP_Social_Auth\Admin;

use Psr\Log\LoggerInterface;
use WP_Social_Auth\Configuration\Configuration;
use WP_Social_Auth\Providers\ProviderFactory;

class Settings_Manager {
    /** @var string Settings option name */
    private const OPTION_NAME = 'wp_social_auth_settings';

    /** @var Configuration */
    private Configuration $config;

    /** @var LoggerInterface */
    private LoggerInterface $logger;

    /** @var ProviderFactory */
    private ProviderFactory $provider_factory;

    /**
     * Constructor.
     *
     * @param Configuration   $config Configuration instance.
     * @param LoggerInterface $logger Logger instance.
     * @param ProviderFactory $provider_factory Provider factory instance.
     */
    public function __construct(
        Configuration $config,
        LoggerInterface $logger,
        ProviderFactory $provider_factory
    ) {
        $this->config = $config;
        $this->logger = $logger;
        $this->provider_factory = $provider_factory;
    }

    /**
     * Initialize settings.
     */
    public function init(): void {
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_menu', [$this, 'add_settings_page']);
    }

    /**
     * Register settings.
     */
    public function register_settings(): void {
        register_setting(
            self::OPTION_NAME,
            self::OPTION_NAME,
            [
                'sanitize_callback' => [$this, 'sanitize_settings'],
                'default' => $this->get_default_settings(),
            ]
        );

        $this->add_settings_sections();
    }

    /**
     * Add settings page.
     */
    public function add_settings_page(): void {
        add_options_page(
            __('Social Authentication', 'wp-social-auth'),
            __('Social Auth', 'wp-social-auth'),
            'manage_options',
            'wp-social-auth',
            [$this, 'render_settings_page']
        );
    }

    /**
     * Add settings sections.
     */
    private function add_settings_sections(): void {
        // Providers Section
        add_settings_section(
            'providers',
            __('Social Providers', 'wp-social-auth'),
            [$this, 'render_providers_section'],
            'wp-social-auth'
        );

        // Registration Section
        add_settings_section(
            'registration',
            __('User Registration', 'wp-social-auth'),
            [$this, 'render_registration_section'],
            'wp-social-auth'
        );

        // Security Section
        add_settings_section(
            'security',
            __('Security', 'wp-social-auth'),
            [$this, 'render_security_section'],
            'wp-social-auth'
        );

        $this->add_settings_fields();
    }

    /**
     * Get default settings.
     *
     * @return array Default settings.
     */
    private function get_default_settings(): array {
        return [
            'providers' => [
                'google' => [
                    'enabled' => false,
                    'client_id' => '',
                    'client_secret' => '',
                ],
                'facebook' => [
                    'enabled' => false,
                    'app_id' => '',
                    'app_secret' => '',
                ],
            ],
            'registration' => [
                'enabled' => true,
                'default_role' => 'subscriber',
                'update_existing' => true,
            ],
            'security' => [
                'rate_limit' => [
                    'enabled' => true,
                    'max_attempts' => 5,
                    'window' => 300,
                ],
            ],
        ];
    }

    /**
     * Render settings page.
     */
    public function render_settings_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <?php settings_errors(); ?>

            <form action="options.php" method="post">
                <?php
                settings_fields(self::OPTION_NAME);
                do_settings_sections('wp-social-auth');
                submit_button(__('Save Settings', 'wp-social-auth'));
                ?>
            </form>
        </div>
        <?php
    }
}
