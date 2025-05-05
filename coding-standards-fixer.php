<?php
/**
 * WordPress Coding Standards Fixer
 *
 * This script adds proper documentation blocks, fixes namespaces
 * and class names to follow WordPress coding standards.
 */

// Define plugin info
$plugin_name = 'WordPress Social Authentication';
$plugin_slug = 'wp-social-auth';
$plugin_prefix = 'WP_Social_Auth_';
$plugin_namespace = 'WP_Social_Auth';
$plugin_package = 'WordPressGmailCli\\SocialAuth';
$plugin_version = '1.0.0';

// Directories to process
$directories = [
    'includes',
    'includes/providers',
    'includes/exceptions',
    'includes/logging',
];

foreach ($directories as $directory) {
    if (!is_dir($directory)) {
        continue;
    }
    
    $files = glob($directory . '/*.php');
    
    foreach ($files as $file) {
        echo "Processing file: $file\n";
        
        // Read file contents
        $content = file_get_contents($file);
        
        // Convert namespace
        $content = preg_replace(
            '/namespace\s+WordPressGmailCli\\\\SocialAuth\\\\[^;]+;/i',
            "namespace $plugin_namespace;",
            $content
        );
        
        // Extract class/interface name
        preg_match('/\b(class|interface|abstract class)\s+([a-zA-Z0-9_]+)/i', $content, $matches);
        
        if (isset($matches[2])) {
            $original_class_name = $matches[2];
            
            // Determine new class name based on file name
            $base_name = basename($file, '.php');
            
            // For interface and abstract class
            if (strpos($base_name, 'interface-') === 0) {
                $wp_class_name = $plugin_prefix . ucfirst(substr($base_name, 10));
                $type = 'Interface';
            } elseif (strpos($base_name, 'abstract-') === 0) {
                $wp_class_name = 'Abstract_' . $plugin_prefix . ucfirst(substr($base_name, 9));
                $type = 'Abstract Class';
            } else {
                // For regular classes
                $wp_class_name = $plugin_prefix . str_replace('-', '_', ucwords(substr($base_name, 6), '-'));
                $type = 'Class';
            }
            
            // Create doc block
            $description = ucfirst(str_replace('-', ' ', substr($base_name, strpos($base_name, '-') + 1)));
            
            $doc_block = "<?php\n/**\n * $description\n *\n * @package $plugin_package\n * @version $plugin_version\n * @since 1.0.0\n */\n\nnamespace $plugin_namespace;\n";
            
            // Replace class/interface name
            $content = preg_replace(
                '/\b(class|interface|abstract class)\s+' . preg_quote($original_class_name, '/') . '\b/i',
                "$1 $wp_class_name",
                $content
            );
            
            // Replace old class name references
            $content = preg_replace(
                '/\b' . preg_quote($original_class_name, '/') . '\b(?!\s*{)/i',
                $wp_class_name,
                $content
            );
            
            // Replace beginning of file with new doc block
            $content = preg_replace('/^<\?php.*?namespace[^;]+;/s', $doc_block, $content);
            
            // Fix use statements
            $content = preg_replace(
                '/use\s+WordPressGmailCli\\\\SocialAuth\\\\([^;]+);/i',
                "use $plugin_namespace\\\\$1;",
                $content
            );
            
            // Write back to file
            file_put_contents($file, $content);
            
            echo "  - Updated $type: $wp_class_name\n";
        } else {
            echo "  - No class/interface found\n";
        }
    }
}

echo "All files processed.\n";
