<?php

use Endroid\QrCode\QrCode;
use Endroid\QrCode\Writer\PngWriter;
use Endroid\QrCode\Encoding\Encoding;
use Endroid\QrCode\ErrorCorrectionLevel;
use Endroid\QrCode\RoundBlockSizeMode;


class userManagment
{
    private $wpdb;
    private $custom_table;

    public function __construct()
    {
        global $wpdb;
        $this->wpdb = $wpdb;
        $this->custom_table = $this->wpdb->prefix . 'custom_users';
    }

    /**
     * Initialize WordPress hooks and actions.
     *
     * @return void
     */
    public function init()
    {
        add_action('acf/save_post', [$this, 'checkAndCreateUser'], 20);
        add_action('acf/save_post', [$this, 'handleUserSaveActions'], 20);
        add_action('template_redirect', [$this, 'checkUserAuthAndRedirect']);
        add_action('template_redirect', [$this, 'handleInviteIdAuth']);
        add_action('wp_ajax_nopriv_ajax_form_sign_up', [$this, 'ajaxFormSignUp']);
        add_action('wp_ajax_ajax_form_sign_up', [$this, 'ajaxFormSignUp']);
        add_action('wp_ajax_nopriv_ajax_form_sign_up_password', [$this, 'ajaxFormSignUpPassword']);
        add_action('wp_ajax_ajax_form_sign_up_password', [$this, 'ajaxFormSignUpPassword']);
        add_action('wp_ajax_nopriv_ajax_form_sign_in', [$this, 'ajaxFormSignIn']);
        add_action('wp_ajax_ajax_form_sign_in', [$this, 'ajaxFormSignIn']);
        add_action('wp_ajax_nopriv_ajax_form_recovery', [$this, 'ajaxFormRecovery']);
        add_action('wp_ajax_ajax_form_recovery', [$this, 'ajaxFormRecovery']);
        add_action('wp_ajax_nopriv_ajax_form_register_group', [$this, 'ajaxFormRegisterGroup']);
        add_action('wp_ajax_ajax_form_register_group', [$this, 'ajaxFormRegisterGroup']);
    }

    /**
     * Check and create users from applications.
     *
     * @return void
     */
    public function checkAndCreateUser()
    {
        $applications = get_field('applications_for_registration', 'option');

        if ($applications) {
            foreach ($applications as $index => $application) {
                if ($this->canProcessApplication($application)) {
                    $this->processApplication($application, $index, $applications);
                }
            }
        }
    }

    /**
     * Validate if an application can be processed.
     *
     * @param array $application Application data.
     * @return bool True if the application can be processed, false otherwise.
     */
    private function canProcessApplication($application)
    {
        return $application['allow'] && empty($application['processed']);
    }

    /**
     * Process an individual application.
     *
     * @param array $application Application data.
     * @param int $index Index of the application in the list.
     * @param array $applications Reference to the applications list.
     * @return void
     */
    private function processApplication($application, $index, &$applications)
    {
        $user_email = sanitize_email($application['email']);
        $user_name = sanitize_text_field($application['name']);

        if ($this->isUserExists($user_email)) {
            return;
        }

        $password = $this->generateAndSaveUser($user_email);
        $this->sendPasswordByEmail($user_email, $user_name, $password);

        $applications[$index]['processed'] = true;

        // Add user to the list of all registered users
        $this->addUserToAllowedUsers($user_email, $password);

        update_field('applications_for_registration', $applications, 'option');
    }

    /**
     * Check if a user already exists in the database.
     *
     * @param string $email User email address.
     * @return bool True if the user exists, false otherwise.
     */
    private function isUserExists($email)
    {
        return $this->wpdb->get_var($this->wpdb->prepare("SELECT id FROM {$this->custom_table} WHERE email = %s", $email)) !== null;
    }

    /**
     * Generate and save a user to the custom table.
     *
     * @param string $email User email address.
     * @param string|null $password Optional password. If not provided, a random password will be generated.
     * @return string Generated or provided password.
     */
    private function generateAndSaveUser($email, $password = null)
    {
        if ($password === null) {
            $password = wp_generate_password(12, false);
        }
        $hashed_password = wp_hash_password($password);

        $existing_user = $this->wpdb->get_var($this->wpdb->prepare("SELECT id FROM {$this->custom_table} WHERE email = %s", $email));

        if ($existing_user) {
            $this->wpdb->update(
                $this->custom_table,
                ['password' => $hashed_password],
                ['email' => $email]
            );
        } else {
            $this->wpdb->insert(
                $this->custom_table,
                [
                    'email' => $email,
                    'password' => $hashed_password,
                ]
            );
        }

        return $password;
    }

    /**
     * Send the generated password to the user via email.
     *
     * @param string $email User email address.
     * @param string $name User name.
     * @param string $password User password.
     * @return void
     */
    private function sendPasswordByEmail($email, $name, $password)
    {
        $email_body = "<h2>Hello, $name!</h2>";
        $email_body .= "<p>Your application has been approved. You can now log in using the credentials below:</p>";
        $email_body .= "<p><strong>Email:</strong> $email</p>";
        $email_body .= "<p><strong>Password:</strong> $password</p><br><br>";
        $email_body .= "<h2>Thank you!</h2>";

        wp_mail($email, 'Application Approved', $email_body, ['Content-Type: text/html; charset=UTF-8']);
    }

    /**
     * Check user authentication and redirect if necessary.
     *
     * @return void
     */
    public function checkUserAuthAndRedirect()
    {
        $allowed_templates = ['page-sign-in.php', 'page-sign-up.php', 'page-password-recovery.php'];

        if (isset($_COOKIE['auth_token'])) {
            $user_id = $this->wpdb->get_var($this->wpdb->prepare(
                "SELECT user_id FROM {$this->wpdb->prefix}user_tokens WHERE token = %s AND expiration > NOW()",
                $_COOKIE['auth_token']
            ));

            if ($user_id && is_front_page() && !is_page('communities')) {
                wp_redirect('/communities');
                exit;
            }
        } else {
            $current_template = basename(get_page_template());

            if (!in_array($current_template, $allowed_templates)) {
                wp_redirect(home_url());
                exit;
            }
        }
    }

    /**
     * Set an authentication cookie for the user.
     *
     * @param int $user_id User ID.
     * @return void
     */
    private function setAuthCookie($user_id)
    {
        $token = bin2hex(random_bytes(16));
        setcookie('auth_token', $token, time() + (86400 * 30), "/");

        $this->wpdb->insert(
            $this->wpdb->prefix . 'user_tokens',
            [
                'user_id' => $user_id,
                'token' => $token,
                'expiration' => date('Y-m-d H:i:s', time() + (86400 * 30)),
            ]
        );
    }

    /**
     * Handle AJAX sign-up form submission.
     *
     * @return void
     */
    public function ajaxFormSignUp()
    {
        check_ajax_referer('ajax-sign-up-nonce', 'security');

        $user_email = sanitize_email($_POST['user_email']);
        $this->validateEmail($user_email);

        if ($this->isUserExists($user_email)) {
            wp_send_json_error('Email already registered');
        }

        $password = $this->generateAndSaveUser($user_email);
        wp_mail($user_email, 'Your Password', 'Your login password: ' . $password);

        $this->addUserToAllowedUsers($user_email, $password);

        wp_send_json_success(['message' => 'Password sent to your email', 'email' => $user_email]);
    }

    /**
     * Validate if the email domain is allowed.
     *
     * @param string $email User email address.
     * @return void
     */
    private function validateEmail($email)
    {
        $allowed_domains = get_field('allowed_email_domains', 'option');
        $allowed_domains_array = array_map(function ($item) {
            return trim(strtolower(ltrim($item['allowed_email_domains_item'], '@')));
        }, $allowed_domains);

        $email_domain = strtolower(substr(strrchr($email, "@"), 1));
        if (!in_array($email_domain, $allowed_domains_array)) {
            wp_send_json_error('Group not found');
        }
    }

    /**
     * Add user to the list of allowed users.
     *
     * @param string $email User email address.
     * @param string $password User password.
     * @return void
     */
    private function addUserToAllowedUsers($email, $password)
    {
        $allowed_users = get_field('allowed_users_form', 'option') ?: [];

        $allowed_users[] = [
            'user_email' => $email,
            'password' => $password,
            'date_creation' => current_time('mysql'),
        ];

        update_field('allowed_users_form', $allowed_users, 'option');
    }

    /**
     * Handle AJAX password recovery form submission.
     *
     * @return void
     */
    public function ajaxFormRecovery()
    {
        check_ajax_referer('ajax-sign-up-nonce', 'security');

        $user_email = sanitize_email($_POST['user_email']);
        $user_data = $this->getUserByEmail($user_email);

        if ($user_data) {
            $new_password = wp_generate_password(12, false);
            $hashed_password = wp_hash_password($new_password);

            $updated = $this->wpdb->update(
                $this->custom_table,
                ['password' => $hashed_password],
                ['email' => $user_email]
            );

            if ($updated !== false) {
                wp_mail($user_email, 'Password Recovery', 'Your new password: ' . $new_password);
                wp_send_json_success(['message' => 'Password has been reset and sent to your email', 'email' => $user_email]);
            } else {
                wp_send_json_error('Failed to update password');
            }
        } else {
            wp_send_json_error('Email not found');
        }
    }

    /**
     * Retrieve user data by email.
     *
     * @param string $email User email address.
     * @return object|null User data object or null if not found.
     */
    private function getUserByEmail($email)
    {
        return $this->wpdb->get_row($this->wpdb->prepare("SELECT * FROM {$this->custom_table} WHERE email = %s", $email));
    }

    /**
     * Send account creation email to the user.
     *
     * @param string $email User email address.
     * @param string $password User password.
     * @param string $date_creation Account creation date.
     * @return void
     */
    private function sendEmailToUser($email, $password, $date_creation)
    {
        $subject = 'Your account has been created';
        $message = "<h2>Hello!</h2>";
        $message .= "<p>Your account has been created.</p>";
        $message .= "<p><strong>Email:</strong> $email</p>";
        $message .= "<p><strong>Password:</strong> $password</p>";
        $message .= "<p><strong>Creation Date:</strong> $date_creation</p><br><br>";
        $message .= "<h2>Thank you!</h2>";

        wp_mail($email, $subject, $message, ['Content-Type: text/html; charset=UTF-8']);
    }

    /**
     * Handle user save actions for the options page.
     *
     * @param int $post_id Post ID being saved.
     * @return void
     */
    public function handleUserSaveActions($post_id)
    {
        if ($post_id !== 'options') {
            return;
        }

        // Process allowed_users_form
        $this->processAllowedUsersForm();

        // Process allowed_users_invite
        $this->processAllowedUsersInvite();
    }

    /**
     * Process updates to the allowed users form.
     *
     * @return void
     */
    private function processAllowedUsersForm()
    {
        $current_users = get_field('allowed_users_form', 'option') ?: [];
        $previous_users = get_option('previous_allowed_users_form') ?: [];

        $removed_users = $this->getRemovedUsers($previous_users, $current_users, 'user_email');

        if ($removed_users) {
            foreach ($removed_users as $user) {
                $this->removeUserFromCustomTable($user['user_email']);
            }
        }

        update_option('previous_allowed_users_form', $current_users);

        if ($current_users) {
            foreach ($current_users as $user) {
                // Add user to custom_users table
                $this->generateAndSaveUser($user['user_email'], $user['password']);

                if ($user['user_email'] && !$this->isEmailSent($user['user_email'])) {
                    $this->sendEmailToUser($user['user_email'], $user['password'], $user['date_creation']);
                    $this->markEmailAsSent($user['user_email']);
                }
            }
        }
    }

    /**
     * Process updates to the allowed users invite form.
     *
     * @return void
     */
    private function processAllowedUsersInvite()
    {
        $current_invite_users = get_field('allowed_users_invite', 'option') ?: [];
        $previous_invite_users = get_option('previous_allowed_users_invite') ?: [];

        $removed_invite_users = $this->getRemovedUsers($previous_invite_users, $current_invite_users, 'user_email_invite');

        if ($removed_invite_users) {
            foreach ($removed_invite_users as $invite_user) {
                $this->removeUserFromCustomTable($invite_user['user_email_invite']);
            }
        }

        update_option('previous_allowed_users_invite', $current_invite_users);

        if ($current_invite_users) {
            foreach ($current_invite_users as $index => $invite_user) {
                $qr_code_id = $this->generateAndSaveQrCode($invite_user['user_email_invite']);

                if ($qr_code_id) {
                    $qr_code_url = wp_get_attachment_url($qr_code_id);

                    $current_invite_users[$index]['qr_code_link_direct'] = [
                        'url' => $qr_code_url,
                        'title' => 'Direct link to QR code',
                        'target' => '_blank'
                    ];

                    $current_invite_users[$index]['qr_code'] = $qr_code_id;
                    // Add user to custom_users table
                    $this->generateAndSaveUser($invite_user['user_email_invite'], $invite_user['password']);

                    update_field('allowed_users_invite', $current_invite_users, 'option');
                }
            }
        }
    }

    /**
     * Get users removed from the list.
     *
     * @param array $previous_users List of previous users.
     * @param array $current_users List of current users.
     * @param string $key Key to compare users.
     * @return array List of removed users.
     */
    private function getRemovedUsers($previous_users, $current_users, $key)
    {
        return array_udiff($previous_users, $current_users, function ($a, $b) use ($key) {
            return strcmp($a[$key], $b[$key]);
        });
    }


    /**
     * Add user to the list of allowed users.
     *
     * @param string $email User email address.
     * @param string $password User password.
     * @return void
     */
    private function addUserToAllowedUsers($email, $password)
    {
        $allowed_users = get_field('allowed_users_form', 'option') ?: [];

        $allowed_users[] = [
            'user_email' => $email,
            'password' => $password,
            'date_creation' => current_time('mysql'),
        ];

        update_field('allowed_users_form', $allowed_users, 'option');
    }

    /**
     * Check if an email has already been sent to the user.
     *
     * @param string $email User email address.
     * @return bool True if the email has been sent, false otherwise.
     */
    private function isEmailSent($email)
    {
        $allowed_users = get_field('allowed_users_form', 'option');

        foreach ($allowed_users as $user) {
            if ($user['user_email'] === $email) {
                // "email_sent" field is stored as a boolean value, check it directly
                return !empty($user['email_sent']);
            }
        }

        return false;
    }

    /**
     * Mark an email as sent for the specified user.
     *
     * @param string $email User email address.
     * @return void
     */
    private function markEmailAsSent($email)
    {
        $allowed_users = get_field('allowed_users_form', 'option');

        foreach ($allowed_users as $index => $user) {
            if ($user['user_email'] === $email) {
                $allowed_users[$index]['email_sent'] = true; // Mark the email as sent
                break; // Stop the loop after finding the user
            }
        }

        update_field('allowed_users_form', $allowed_users, 'option');
    }

    /**
     * Remove a user from the custom table.
     *
     * @param string $email User email address.
     * @return void
     */
    private function removeUserFromCustomTable($email)
    {
        $this->wpdb->delete(
            $this->custom_table,
            ['email' => $email]
        );
    }

    /**
     * Handle invite ID authentication.
     *
     * @return void
     */
    public function handleInviteIdAuth()
    {
        if (isset($_GET['invite_id'])) {
            $invite_id = sanitize_text_field($_GET['invite_id']);

            // Check if the invite link has expired
            $expiration_date = '2024-10-20';
            $current_date = date('Y-m-d');

            if ($current_date > $expiration_date) {
                wp_die('The invite link has expired.');
            }

            // Find user by invite ID in the database
            $user = $this->getUserByInviteId($invite_id);

            if ($user) {
                // Set cookie for authentication
                $this->setAuthCookie($user->id);

                // Redirect to /communities page
                wp_redirect('/communities');
                exit;
            } else {
                wp_die('Invalid invite ID');
            }
        }
    }

    /**
     * Retrieve user data by invite ID.
     *
     * @param string $invite_id Invite ID.
     * @return object|null User data object or null if not found.
     */
    private function getUserByInviteId($invite_id)
    {
        return $this->wpdb->get_row($this->wpdb->prepare("SELECT id FROM {$this->custom_table} WHERE email = %s", $invite_id));
    }

    /**
     * Generate and save a QR code for the invite ID.
     *
     * @param string $invite_id Invite ID.
     * @return int|null Attachment ID of the saved QR code or null on failure.
     */
    private function generateAndSaveQrCode($invite_id)
    {
        try {
            // URL to be encoded in the QR code
            $site_url = home_url();
            $auth_url = add_query_arg('invite_id', $invite_id, $site_url);

            // Create the QR code
            $qrCode = QrCode::create($auth_url)
                ->setEncoding(new Encoding('UTF-8'))
                ->setErrorCorrectionLevel(ErrorCorrectionLevel::Low)
                ->setSize(300)
                ->setMargin(10)
                ->setRoundBlockSizeMode(RoundBlockSizeMode::Margin);

            $writer = new PngWriter();
            $result = $writer->write($qrCode);

            // Save the QR code to a file
            $upload_dir = wp_upload_dir();
            $file_name = $invite_id . '.png';
            $file_path = $upload_dir['path'] . '/' . $file_name;
            file_put_contents($file_path, $result->getString());

            // Add the file to the WordPress media library and get its ID
            $attachment_id = $this->addImageToMediaLibrary($file_path, $file_name);

            return $attachment_id;
        } catch (Exception $e) {
            error_log("Error generating QR Code: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Add an image to the WordPress media library.
     *
     * @param string $file_path Path to the image file.
     * @param string $file_name Name of the image file.
     * @return int|null Attachment ID of the uploaded image or null on failure.
     */
    private function addImageToMediaLibrary($file_path, $file_name)
    {
        $upload_file = wp_upload_bits($file_name, null, file_get_contents($file_path));
        if (!$upload_file['error']) {
            $wp_filetype = wp_check_filetype($file_name, null);
            $attachment = array(
                'post_mime_type' => $wp_filetype['type'],
                'post_title' => sanitize_file_name($file_name),
                'post_content' => '',
                'post_status' => 'inherit'
            );
            $attachment_id = wp_insert_attachment($attachment, $upload_file['file']);
            require_once(ABSPATH . 'wp-admin/includes/image.php');
            $attachment_data = wp_generate_attachment_metadata($attachment_id, $upload_file['file']);
            wp_update_attachment_metadata($attachment_id, $attachment_data);
            return $attachment_id;
        }
        return null;
    }
}

$userManagment = new userManagment();
$userManagment->init();
