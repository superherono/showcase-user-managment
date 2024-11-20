# User Management Plugin

This plugin is designed to manage custom user data and integrates advanced features such as QR code generation using the WordPress platform. It leverages `ACF` hooks and custom database table manipulation for streamlined operations.

## Features

- **Custom User Management:** Save and manage user data in a custom database table.
- **QR Code Generation:** Generate QR codes for user-specific data using the `Endroid QR Code` library.
- **ACF Integration:** Automatically handle data submissions from ACF forms.

## Installation

1. Ensure WordPress is installed and configured.
2. Upload the plugin files to the `wp-content/plugins/` directory.
3. Activate the plugin from the WordPress dashboard.

## Usage

- **ACF Form Hook:** The plugin automatically processes `acf/save_post` actions for the `custom_post_type`.
- **Database Table:** User data is stored in the `{wpdb_prefix}_custom_users` table.
- **QR Code Path:** Generated QR codes are saved in the `wp-content/uploads/qrcodes/` directory.

## Requirements

- WordPress 5.0 or higher.
- Advanced Custom Fields (ACF) plugin installed.
- PHP 7.4 or higher.

## Configuration

- Customize the table name or post type in the `userManagment` class.
- Ensure the uploads directory has write permissions for saving QR codes.

## License

This project is licensed under the MIT License.
