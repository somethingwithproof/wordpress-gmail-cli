#!/bin/bash

# WordPress Coding Standards Fixer Script
# This script automates fixing common WordPress coding standards issues:
# 1. Renames files according to WordPress naming conventions
# 2. Runs PHPCBF to fix indentation and other automatically fixable issues
# 3. Executes a PHP script to add proper documentation and fix class names

echo "Starting WordPress Coding Standards Fix..."

# 1. Create new directory structure
echo "Creating WordPress compliant directory structure..."
mkdir -p includes

# 2. Rename files according to WordPress naming conventions
echo "Renaming files to follow WordPress naming conventions..."

# Process src/Configuration
if [ -d "src/Configuration" ]; then
    mkdir -p includes/class-configuration
    # Configuration class
    if [ -f "src/Configuration/Configuration.php" ]; then
        cp src/Configuration/Configuration.php includes/class-configuration.php
    fi
fi

# Process src/Providers directory
if [ -d "src/Providers" ]; then
    mkdir -p includes/providers
    
    # Provider interface
    if [ -f "src/Providers/ProviderInterface.php" ]; then
        cp src/Providers/ProviderInterface.php includes/providers/interface-provider.php
    fi
    
    # Abstract provider
    if [ -f "src/Providers/AbstractProvider.php" ]; then
        cp src/Providers/AbstractProvider.php includes/providers/abstract-provider.php
    fi
    
    # Google provider
    if [ -f "src/Providers/GoogleProvider.php" ]; then
        cp src/Providers/GoogleProvider.php includes/providers/class-google-provider.php
    fi
    
    # Provider factory
    if [ -f "src/Providers/ProviderFactory.php" ]; then
        cp src/Providers/ProviderFactory.php includes/providers/class-provider-factory.php
    fi
fi

# Process src/Exception directory
if [ -d "src/Exception" ]; then
    mkdir -p includes/exceptions
    
    # Auth exception
    if [ -f "src/Exception/AuthException.php" ]; then
        cp src/Exception/AuthException.php includes/exceptions/class-auth-exception.php
    fi
    
    # Config exception
    if [ -f "src/Exception/ConfigException.php" ]; then
        cp src/Exception/ConfigException.php includes/exceptions/class-config-exception.php
    fi
    
    # Provider exception
    if [ -f "src/Exception/ProviderException.php" ]; then
        cp src/Exception/ProviderException.php includes/exceptions/class-provider-exception.php
    fi
    
    # Rate limit exception
    if [ -f "src/Exception/RateLimitException.php" ]; then
        cp src/Exception/RateLimitException.php includes/exceptions/class-rate-limit-exception.php
    fi
fi

# Process src/Logging directory
if [ -d "src/Logging" ]; then
    mkdir -p includes/logging
    
    # Logger class
    if [ -f "src/Logging/Logger.php" ]; then
        cp src/Logging/Logger.php includes/logging/class-logger.php
    fi
fi

# Plugin class
if [ -f "src/Plugin.php" ]; then
    cp src/Plugin.php includes/class-wp-social-auth.php
fi

# 3. Run PHPCBF to fix indentation and other auto-fixable issues
echo "Running PHPCBF to fix indentation and other auto-fixable issues..."
vendor/bin/phpcbf --standard=WordPress includes/

# 4. Run PHP fixer script to add doc blocks and fix class naming
echo "Creating PHP fixer script..."
cat > coding-standards-fixer.php << 'PHP_SCRIPT'
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
PHP_SCRIPT

echo "Running PHP fixer script..."
php coding-standards-fixer.php

echo "WordPress Coding Standards Fix complete!"
echo "Please review changes and make any necessary manual adjustments."

