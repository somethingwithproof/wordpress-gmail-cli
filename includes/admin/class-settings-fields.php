<?php
/**
 * Settings Fields
 *
 * @package WordPress Social Authentication
 * @since 1.0.0
 */

namespace WP_Social_Auth\Admin;

trait Settings_Fields {
    /**
     * Render Google authentication fields.
     */
    public function render_google_fields(): void {
        $settings = get_option('wp_social_auth_settings');
        $enabled = isset($settings['providers']['google']['enabled']) ? (bool) $settings['providers']['google']['enabled'] : false;
        $client_id = $settings['providers']['google']['client_id'] ?? '';
        $client_secret = $settings['providers']['google']['client_secret'] ?? '';
        ?>
        <fieldset>
            <legend class="screen-reader-text">
                <?php esc_html_e('Google Authentication Settings', 'wp-social-auth'); ?>
            </legend>

            <p>
                <label>
                    <input type="checkbox" 
                           name="wp_social_auth_settings[providers][google][enabled]" 
                           value="1" 
                           <?php checked($enabled); ?>
                    />
                    <?php esc_html_e('Enable Google Authentication', 'wp-social-auth'); ?>
                </label>
            </p>

            <div class="provider-settings <?php echo $enabled ? '' : 'hidden'; ?>">
                <p>
                    <label for="google_client_id">
                        <?php esc_html_e('Client ID', 'wp-social-auth'); ?>
                    </label>
                    <input type="text"
                           id="google_client_id"
                           name="wp_social_auth_settings[providers][google][client_id]"
                           value="<?php echo esc_attr($client_id); ?>"
                           class="regular-text"
                    />
                </p>

                <p>
                    <label for="google_client_secret">
                        <?php esc_html_e('Client Secret', 'wp-social-auth'); ?>
                    </label>
                    <input type="password"
                           id="google_client_secret"
                           name="wp_social_auth_settings[providers][google][client_secret]"
                           value="<?php echo esc_attr($client_secret); ?>"
                           class="regular-text"
                    />
                </p>

                <p class="description">
                    <?php
                    printf(
                        /* translators: %s: Google Cloud Console URL */
                        esc_html__('Create credentials in the %s.', 'wp-social-auth'),
                        '<a href="https://console.cloud.google.com/apis/credentials" target="_blank">' . 
                        esc_html__('Google Cloud Console', 'wp-social-auth') . 
                        '</a>'
                    );
                    ?>
                </p>
            </div>
        </fieldset>
        <?php
    }

    /**
     * Render Facebook authentication fields.
     */
    public function render_facebook_fields(): void {
        $settings = get_option('wp_social_auth_settings');
        $enabled = isset($settings['providers']['facebook']['enabled']) ? (bool) $settings['providers']['facebook']['enabled'] : false;
        $app_id = $settings['providers']['facebook']['app_id'] ?? '';
        $app_secret = $settings['providers']['facebook']['app_secret'] ?? '';
        ?>
        <fieldset>
            <legend class="screen-reader-text">
                <?php esc_html_e('Facebook Authentication Settings', 'wp-social-auth'); ?>
            </legend>

            <p>
                <label>
                    <input type="checkbox" 
                           name="wp_social_auth_settings[providers][facebook][enabled]" 
                           value="1" 
                           <?php checked($enabled); ?>
                    />
                    <?php esc_html_e('Enable Facebook Authentication', 'wp-social-auth'); ?>
                </label>
            </p>

            <div class="provider-settings <?php echo $enabled ? '' : 'hidden'; ?>">
                <p>
                    <label for="facebook_app_id">
                        <?php esc_html_e('App ID', 'wp-social-auth'); ?>
                    </label>
                    <input type="text"
                           id="facebook_app_id"
                           name="wp_social_auth_settings[providers][facebook][app_id]"
                           value="<?php echo esc_attr($app_id); ?>"
                           class="regular-text"
                    />
                </p>

                <p>
                    <label for="facebook_app_secret">
                        <?php esc_html_e('App Secret', 'wp-social-auth'); ?>
                    </label>
                    <input type="password"
                           id="facebook_app_secret"
                           name="wp_social_auth_settings[providers][facebook][app_secret]"
                           value="<?php echo esc_attr($app_secret); ?>"
                           class="regular-text"
                    />
                </p>

                <p class="description">
                    <?php
                    printf(
                        /* translators: %s: Facebook Developers URL */
                        esc_html__('Create an app in the %s.', 'wp-social-auth'),
                        '<a href="https://developers.facebook.com/apps/" target="_blank">' . 
                        esc_html__('Facebook Developers Console', 'wp-social-auth') . 
                        '</a>'
                    );
                    ?>
                </p>
            </div>
        </fieldset>
        <?php
    }

    /**
     * Render checkbox field.
     *
     * @param array $args Field arguments.
     */
    public function render_checkbox_field(array $args): void {
        $settings = get_option('wp_social_auth_settings');
        $value = $this->get_nested_array_value($settings, explode('[', str_replace(']', '', $args['name'])));
        ?>
        <label>
            <input type="checkbox"
                   id="<?php echo esc_attr($args['id']); ?>"
                   name="wp_social_auth_settings[<?php echo esc_attr($args['name']); ?>]"
                   value="1"
                   <?php checked((bool) $value); ?>
            />
            <?php echo esc_html($args['description']); ?>
        </label>
        <?php
    }

    /**
     * Render role select field.
     */
    public function render_role_select(): void {
        $settings = get_option('wp_social_auth_settings');
        $current_role = $settings['registration']['default_role'] ?? 'subscriber';
        ?>
        <select name="wp_social_auth_settings[registration][default_role]" id="default_role">
            <?php
            $roles = get_editable_roles();
            foreach ($roles as $role => $details) {
                ?>
                <option value="<?php echo esc_attr($role); ?>"
                        <?php selected($current_role, $role); ?>>
                    <?php echo esc_html(translate_user_role($details['name'])); ?>
                </option>
                <?php
            }
            ?>
        </select>
        <p class="description">
            <?php esc_html_e('The default role assigned to new users.', 'wp-social-auth'); ?>
        </p>
        <?php
    }

    /**
     * Render rate limit fields.
     */
    public function render_rate_limit_fields(): void {
        $settings = get_option('wp_social_auth_settings');
        $enabled = isset($settings['security']['rate_limit']['enabled']) 
            ? (bool) $settings['security']['rate_limit']['enabled'] 
            : true;
        $max_attempts = $settings['security']['rate_limit']['max_attempts'] ?? 5;
        $window = $settings['security']['rate_limit']['window'] ?? 300;
        ?>
        <fieldset>
            <legend class="screen-reader-text">
                <?php esc_html_e('Rate Limiting Settings', 'wp-social-auth'); ?>
            </legend>

            <p>
                <label>
                    <input type="checkbox"
                           name="wp_social_auth_settings[security][rate_limit][enabled]"
                           value="1"
                           <?php checked($enabled); ?>
                    />
                    <?php esc_html_e('Enable rate limiting', 'wp-social-auth'); ?>
                </label>
            </p>

            <div class="rate-limit-settings <?php echo $enabled ? '' : 'hidden'; ?>">
                <p>
                    <label for="rate_limit_max_attempts">
                        <?php esc_html_e('Maximum attempts:', 'wp-social-auth'); ?>
                    </label>
                    <input type="number"
                           id="rate_limit_max_attempts"
                           name="wp_social_auth_settings[security][rate_limit][max_attempts]"
                           value="<?php echo esc_attr($max_attempts); ?>"
                           min="1"
                           class="small-text"
                    />
                </p>

                <p>
                    <label for="rate_limit_window">
                        <?php esc_html_e('Time window (seconds):', 'wp-social-auth'); ?>
                    </label>
                    <input type="number"
                           id="rate_limit_window"
                           name="wp_social_auth_settings[security][rate_limit][window]"
                           value="<?php echo esc_attr($window); ?>"
                           min="60"
                           step="60"
                           class="small-text"
                    />
                </p>
            </div>
        </fieldset>
        <?php
    }

    /**
     * Get nested array value.
     *
     * @param array $array Array to search.
     * @param array $keys Keys to traverse.
     * @return mixed|null Value if found, null otherwise.
     */
    private function get_nested_array_value(array $array, array $keys) {
        foreach ($keys as $key) {
            if (!isset($array[$key])) {
                return null;
            }
            $array = $array[$key];
        }
        return $array;
    }
}
