<?php

namespace WordPressGmailCli\SocialAuth;

use Psr\Log\LoggerInterface;
use WordPressGmailCli\SocialAuth\Authentication\AuthenticationManager;
use WordPressGmailCli\SocialAuth\Configuration\Configuration;
use WordPressGmailCli\SocialAuth\Exception\ConfigException;
use WordPressGmailCli\SocialAuth\Logging\Logger;
use WordPressGmailCli\SocialAuth\Providers\ProviderFactory;
use WordPressGmailCli\SocialAuth\Settings\SettingsManager;
use WordPressGmailCli\SocialAuth\UserManagement\UserManager;

/**
 * Main plugin class.
 */
class Plugin
{
    /**
     * Plugin instance.
     *
     * @var self|null
     */
    private static ?self $instance = null;

    /**
     * Plugin version.
     *
     * @var string
     */
    private string $version;

    /**
     * Configuration instance.
     *
     * @var Configuration
     */
    private Configuration $config;

    /**
     * Logger instance.
     *
     * @var LoggerInterface
     */
    private LoggerInterface $logger;

    /**
     * Provider factory instance.
     *
     * @var ProviderFactory
     */
    private ProviderFactory $providerFactory;

    /**
     * Authentication manager instance.
     *
     * @var AuthenticationManager|null
     */
    private ?AuthenticationManager $authenticationManager = null;

    /**
     * User manager instance.
     *
     * @var UserManager|null
     */
    private ?UserManager $userManager = null;

    /**
     * Settings manager instance.
     *
     * @var SettingsManager|null
     */
    private ?SettingsManager $settingsManager = null;

    /**
     * Get plugin instance.
     *
     * @return self Plugin instance.
     */
    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Private constructor to enforce singleton pattern.
     */
    private function __construct()
    {
        $this->version = '1.0.0';
        $this->initializeComponents();
    }

    /**
     * Initialize plugin components.
     */
    private function initializeComponents(): void
    {
        // Initialize configuration
        $this->config = new Configuration([
            'plugin' => [
                'version' => $this->version,
            ],
        ]);

        // Initialize logger
        $this->logger = new Logger('wp-social-auth');
        
        // If debug is enabled, set more verbose logging
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->logger->setMinimumLevel('debug');
        }

        // Initialize provider factory
        $this->providerFactory = new ProviderFactory($this->logger);

        // Initialize WordPress hooks
        $this->registerHooks();
        
        // Log initialization
        $this->logger->info('Plugin initialized', [
            'version' => $this->version,
        ]);
    }

    /**
     * Register WordPress hooks.
     */
    private function registerHooks(): void
    {
        // Plugin activation/deactivation hooks
        register_activation_hook(WP_SOCIAL_AUTH_FILE, [$this, 'activate']);
        register_deactivation_hook(WP_SOCIAL_AUTH_FILE, [$this, 'deactivate']);
        
        // Plugin initialization
        add_action('plugins_loaded', [$this, 'initPlugin']);
        
        // Admin hooks (only load in admin)
        if (is_admin()) {
            add_action('admin_init', [$this, 'initAdmin']);
            add_filter('plugin_action_links', [$this, 'addPluginLinks'], 10, 2);
        }
        
        // Login form hooks
        add_action('login_enqueue_scripts', [$this, 'enqueueLoginAssets']);
        add_action('login_form', [$this, 'renderLoginButtons']);
        add_action('register_form', [$this, 'renderLoginButtons']);
        
        // AJAX actions for authentication
        add_action('wp_ajax_nopriv_social_login_callback', [$this, 'handleAuthCallback']);
        add_action('wp_ajax_social_login_callback', [$this, 'handleAuthCallback']);
    }

    /**
     * Plugin activation handler.
     */
    public function activate(): void
    {
        // Check PHP version
        $minPhpVersion = $this->config->get('plugin.min_php_version', '7.4');
        if (version_compare(PHP_VERSION, $minPhpVersion, '<')) {
            // Deactivate plugin and show error
            deactivate_plugins(plugin_basename(WP_SOCIAL_AUTH_FILE));
            wp_die(
                sprintf(
                    'WordPress Social Authentication requires PHP %s or higher. You are running PHP %s.',
                    $minPhpVersion,
                    PHP_VERSION
                ),
                'Plugin Activation Error',
                ['back_link' => true]
            );
        }

        // Check WordPress version
        global $wp_version;
        $minWpVersion = $this->config->get('plugin.min_wp_version', '5.8');
        if (version_compare($wp_version, $minWpVersion, '<')) {
            deactivate_plugins(plugin_basename(WP_SOCIAL_AUTH_FILE));
            wp_die(
                sprintf(
                    'WordPress Social Authentication requires WordPress %s or higher. You are running WordPress %s.',
                    $minWpVersion,
                    $wp_version
                ),
                'Plugin Activation Error',
                ['back_link' => true]
            );
        }

        // Create necessary database tables if needed
        // $this->createTables();

        // Save default configuration
        $this->config->save();

        // Log activation
        $this->logger->info('Plugin activated', [
            'version' => $this->version,
            'php_version' => PHP_VERSION,
            'wp_version' => $wp_version,
        ]);
    }

    /**
     * Plugin deactivation handler.
     */
    public function deactivate(): void
    {
        // Clean up transients
        global $wpdb;
        
        if (isset($wpdb) && $wpdb instanceof \wpdb) {
            $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
                    $wpdb->esc_like('_transient_wp_social_auth_') . '%'
                )
            );
        }

        // Log deactivation
        $this->logger->info('Plugin deactivated');
    }

    /**
     * Initialize plugin after WordPress is fully loaded.
     */
    public function initPlugin(): void
    {
        // Load text domain for internationalization
        load_plugin_textdomain(
            'wp-social-auth',
            false,
            dirname(plugin_basename(WP_SOCIAL_AUTH_FILE)) . '/languages'
        );

        try {
            // Initialize user manager
            $this->getUserManager();
            
            // Initialize authentication manager
            $this->getAuthenticationManager();
            
            // Run plugin compatibility checks
            $this->runCompatibilityChecks();
        } catch (\Exception $e) {
            $this->logger->error('Error initializing plugin', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            
            // Add admin notice for errors
            add_action('admin_notices', function() use ($e) {
                printf(
                    '<div class="notice notice-error"><p>%s</p></div>',
                    esc_html('WordPress Social Authentication error: ' . $e->getMessage())
                );
            });
        }
    }

    /**
     * Initialize admin functionality.
     */
    public function initAdmin(): void
    {
        // Initialize settings manager for admin
        $this->getSettingsManager()->registerSettings();
        
        // Add settings page to admin menu
        add_action('admin_menu', [$this->getSettingsManager(), 'addSettingsPage']);
    }

    /**
     * Get authentication manager, creating it if needed.
     * 
     * @return AuthenticationManager
     */
    public function getAuthenticationManager(): AuthenticationManager
    {
        if ($this->authenticationManager === null) {
            // We'll implement this class later
            $this->authenticationManager = new AuthenticationManager(
                $this->providerFactory,
                $this->getUserManager(),
                $this->config,
                $this->logger
            );
        }
        
        return $this->authenticationManager;
    }

    /**
     * Get user manager, creating it if needed.
     * 
     * @return UserManager
     */
    public function getUserManager(): UserManager
    {
        if ($this->userManager === null) {
            // We'll implement this class later
            $this->userManager = new UserManager(
                $this->config,
                $this->logger
            );
        }
        
        return $this->userManager;
    }

    /**
     * Get settings manager, creating it if needed.
     * 
     * @return SettingsManager
     */
    public function getSettingsManager(): SettingsManager
    {
        if ($this->settingsManager === null) {
            // We'll implement this class later
            $this->settingsManager = new SettingsManager(
                $this->config,
                $this->logger,
                $this->providerFactory
            );
        }
        
        return $this->settingsManager;
    }

    /**
     * Enqueue assets for login page.
     */
    public function enqueueLoginAssets(): void
    {
        wp_enqueue_style(
            'wp-social-auth-login',
            plugin_dir_url(WP_SOCIAL_AUTH_FILE) . 'assets/css/login.css',
            [],
            $this->version
        );
    }

    /**
     * Render social login buttons on login and registration forms.
     */
    public function renderLoginButtons(): void
    {
        try {
            $providers = $this->providerFactory->getConfiguredProviders();
            
            if (empty($providers)) {
                return;
            }
            
            // Use path for require to allow access to local variables
            require_once dirname(WP_SOCIAL_AUTH_FILE) . '/templates/login-buttons.php';
            
        } catch (\Exception $e) {
            $this->logger->error('Error rendering login buttons', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Handle authentication callback from social providers.
     */
    public function handleAuthCallback(): void
    {
        try {
            $this->getAuthenticationManager()->handleCallback();
        } catch (\Exception $e) {
            $this->logger->error('Authentication callback error', [
                'error' => $e->getMessage(),
            ]);
            
            // Redirect to login page with error
            wp_safe_redirect(
                add_query_arg(
                    [
                        'login' => 'failed',
                        'reason' => 'provider_error',
                        'error' => urlencode($e->getMessage()),
                    ],
                    wp_login_url()
                )
            );
            exit;
        }
    }

    /**
     * Add plugin action links.
     *
     * @param array $links Existing plugin action links.
     * @param string $file Plugin file.
     * @return array Modified plugin action links.
     */
    public function addPluginLinks(array $links, string $file): array
    {
        if (plugin_basename(WP_SOCIAL_AUTH_FILE) === $file) {
            $settingsLink = sprintf(
                '<a href="%s">%s</a>',
                admin_url('options-general.php?page=wp-social-auth-settings'),
                __('Settings', 'wp-social-auth')
            );
            
            array_unshift($links, $settingsLink);
        }
        
        return $links;
    }

    /**
     * Run compatibility checks for the plugin.
     */
    private function runCompatibilityChecks(): void
    {
        // Check if required extensions are loaded
        foreach (['json', 'curl'] as $extension) {
            if (!extension_loaded($extension)) {
                $this->logger->warning("PHP extension not loaded: {$extension}");
            }
        }
        
        // Check if HTTPS is available for secure authentication
        if (!is_ssl() && !wp_doing_ajax() && is_admin()) {
            add_action('admin_notices', function() {
                printf(
                    '<div class="notice notice-warning"><p>%s</p></div>',
                    esc_html__(
                        'For security reasons, WordPress Social Authentication works best with HTTPS. Please consider enabling HTTPS on your site.',
                        'wp-social-auth'
                    )
                );
            });
        }
    }

    /**
     * Get configuration instance.
     *
     * @return Configuration
     */
    public function getConfig(): Configuration
    {
        return $this->config;
    }

    /**
     * Get logger instance.
     *
     * @return LoggerInterface
     */
    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    /**
     * Get provider factory instance.
     *
     * @return ProviderFactory
     */
    public function getProviderFactory(): ProviderFactory
    {
        return $this->providerFactory;
    }
    
    /**
     * Get plugin version.
     *
     * @return string
     */
    public function getVersion(): string
    {
        return $this->version;
    }
}

