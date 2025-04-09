<?php
/**
 * Plugin Name: SSO Integration
 * Description: Seamless authentication across services
 * Version: 1.0
 * Author: Your Name
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class SSO_Integration {
    private $sso_url;
    private $api_key;
    private $api_secret;
    private $cookie_name;
    
    public function __construct() {
        // Load settings
        $this->sso_url = get_option('sso_integration_url');
        $this->api_key = get_option('sso_integration_api_key');
        $this->api_secret = get_option('sso_integration_api_secret');
        $this->cookie_name = get_option('sso_integration_cookie_name', 'sso_auth_token');
        
        // Add hooks
        add_action('init', [$this, 'check_sso_authentication']);
        add_filter('authenticate', [$this, 'authenticate'], 10, 3);
        add_action('wp_logout', [$this, 'logout']);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
    }
    
    /**
     * Check if user has SSO cookie and authenticate them
     */
    public function check_sso_authentication() {
        // Skip if user is already logged in
        if (is_user_logged_in()) {
            return;
        }
        
        // Check for SSO cookie
        if (!isset($_COOKIE[$this->cookie_name])) {
            return;
        }
        
        $token = $_COOKIE[$this->cookie_name];
        
        // Validate token with SSO service
        $response = wp_remote_post($this->sso_url . '/api/auth/validate', [
            'body' => [
                'token' => $token,
                'api_key' => $this->api_key,
                'api_secret' => $this->api_secret
            ]
        ]);
        
        if (is_wp_error($response)) {
            return;
        }
        
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!isset($body['valid']) || $body['valid'] !== true) {
            return;
        }
        
        // Get user details
        $user_data = $body['user'];
        
        // Look for existing user
        $user = get_user_by('email', $user_data['email']);
        
        // Create user if doesn't exist
        if (!$user) {
            $user_id = wp_create_user(
                $user_data['username'],
                wp_generate_password(24),
                $user_data['email']
            );
            
            if (is_wp_error($user_id)) {
                return;
            }
            
            $user = get_user_by('id', $user_id);
            
            // Set display name
            wp_update_user([
                'ID' => $user_id,
                'display_name' => $user_data['first_name'] . ' ' . $user_data['last_name']
            ]);
        }
        
        // Log the user in
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);
        
        // Fire hook for other plugins
        do_action('wp_login', $user->user_login, $user);
    }
    
    /**
     * Hook into WordPress authentication
     */
    public function authenticate($user, $username, $password) {
        if ($user instanceof WP_User) {
            return $user;
        }
        
        if (empty($username) || empty($password)) {
            return $user;
        }
        
        // Authenticate against SSO
        $response = wp_remote_post($this->sso_url . '/api/auth/login', [
            'body' => [
                'username' => $username,
                'password' => $password,
                'api_key' => $this->api_key,
                'api_secret' => $this->api_secret,
                'service' => 'wordpress'
            ]
        ]);
        
        if (is_wp_error($response)) {
            return $user;
        }
        
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!isset($body['success']) || $body['success'] !== true) {
            return $user;
        }
        
        // Set SSO cookie - this is handled by the SSO service
        
        // Get user data
        $user_data = $body['user'];
        
        // Find or create WordPress user
        $wp_user = get_user_by('email', $user_data['email']);
        
        if (!$wp_user) {
            $user_id = wp_create_user(
                $user_data['username'],
                wp_generate_password(24),
                $user_data['email']
            );
            
            if (is_wp_error($user_id)) {
                return null;
            }
            
            $wp_user = get_user_by('id', $user_id);
        }
        
        return $wp_user;
    }
    
    /**
     * Logout from SSO when logging out from WordPress
     */
    public function logout() {
        if (!isset($_COOKIE[$this->cookie_name])) {
            return;
        }
        
        $token = $_COOKIE[$this->cookie_name];
        
        // Call SSO logout
        wp_remote_post($this->sso_url . '/api/auth/logout', [
            'body' => [
                'token' => $token,
                'api_key' => $this->api_key,
                'api_secret' => $this->api_secret
            ]
        ]);
        
        // Cookie will be cleared by SSO service
    }
    
    /**
     * Add admin settings page
     */
    public function add_admin_menu() {
        add_options_page(
            'SSO Integration',
            'SSO Integration',
            'manage_options',
            'sso-integration',
            [$this, 'render_settings_page']
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('sso_integration', 'sso_integration_url');
        register_setting('sso_integration', 'sso_integration_api_key');
        register_setting('sso_integration', 'sso_integration_api_secret');
        register_setting('sso_integration', 'sso_integration_cookie_name');
    }
    
    /**
     * Render settings page
     */
    public function render_settings_page() {
        ?>
        <div class="wrap">
            <h1>SSO Integration Settings</h1>
            <form method="post" action="options.php">
                <?php settings_fields('sso_integration'); ?>
                <?php do_settings_sections('sso_integration'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row">SSO Service URL</th>
                        <td>
                            <input type="text" name="sso_integration_url" 
                                   value="<?php echo esc_attr(get_option('sso_integration_url')); ?>" 
                                   class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">API Key</th>
                        <td>
                            <input type="text" name="sso_integration_api_key" 
                                   value="<?php echo esc_attr(get_option('sso_integration_api_key')); ?>" 
                                   class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">API Secret</th>
                        <td>
                            <input type="password" name="sso_integration_api_secret" 
                                   value="<?php echo esc_attr(get_option('sso_integration_api_secret')); ?>" 
                                   class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Cookie Name</th>
                        <td>
                            <input type="text" name="sso_integration_cookie_name" 
                                   value="<?php echo esc_attr(get_option('sso_integration_cookie_name', 'sso_auth_token')); ?>" 
                                   class="regular-text" />
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}

// Initialize the plugin
new SSO_Integration();