<?php

use Endroid\QrCode\QrCode;
use Endroid\QrCode\Writer\PngWriter;
use Endroid\QrCode\Encoding\Encoding;
use Endroid\QrCode\ErrorCorrectionLevel;
use Endroid\QrCode\RoundBlockSizeMode;

class userManagment
{
    // WordPress database object and custom table name
    private $wpdb;
    private $custom_table;

    public function __construct()
    {
        // Access global $wpdb object
        global $wpdb;
        $this->wpdb = $wpdb;

        // Define the custom table name with WordPress prefix
        $this->custom_table = $this->wpdb->prefix . 'custom_users';
    }

    // Initialize the plugin by attaching WordPress hooks
    public function init()
    {
        // Hook to handle actions after ACF form submission
        add_action('acf/save_post', [$this, 'handle_save_post']);
    }

    // Handle saving custom user data upon ACF form submission
    public function handle_save_post($post_id)
    {
        // Perform actions only for a specific post type
        if (get_post_type($post_id) !== 'custom_post_type') {
            return;
        }

        // Custom logic to handle the saved data
        $data = $_POST['custom_field'] ?? '';
        if ($data) {
            $this->save_user_data($data);
        }
    }

    // Save user data into the custom database table
    private function save_user_data($data)
    {
        $this->wpdb->insert($this->custom_table, [
            'user_data' => $data,
            'created_at' => current_time('mysql'),
        ]);
    }

    // Generate a QR code and return its path
    public function generate_qr_code($data)
    {
        $qrCode = new QrCode($data);
        $qrCode->setEncoding(new Encoding('UTF-8'))
            ->setErrorCorrectionLevel(new ErrorCorrectionLevel(ErrorCorrectionLevel::HIGH))
            ->setRoundBlockSizeMode(new RoundBlockSizeMode(RoundBlockSizeMode::SHRINK));

        $writer = new PngWriter();
        $path = ABSPATH . 'wp-content/uploads/qrcodes/' . uniqid() . '.png';
        $writer->write($qrCode)->saveToFile($path);

        return $path;
    }
}
