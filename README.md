# User Management Codebase

This codebase is designed to demonstrate an advanced user management system in WordPress, integrating features such as custom user tables, authentication using cookies, and QR code generation. It is intended as an example of robust back-end development in WordPress, utilizing best practices for database interactions, security, and extendability.

## Features

1. **Custom User Management**:
   - Users are stored in a custom database table (`custom_users`).
   - Includes functions to create, update, and delete users.

2. **Email Notifications**:
   - Automatically sends emails to users with credentials or recovery information.
   - Tracks whether emails have been sent.

3. **QR Code Generation**:
   - Generates QR codes for invite-based authentication.
   - QR codes are stored in the WordPress media library.

4. **Advanced Authentication**:
   - Implements cookie-based authentication with token expiration.
   - Handles invite link authentication with expiration checks.

5. **Integration with Advanced Custom Fields (ACF)**:
   - Manages user data and settings using ACF fields.
   - Automatically processes and synchronizes ACF-based user lists.

6. **AJAX Support**:
   - Includes AJAX handlers for user registration, login, and password recovery.

## Prerequisites

- **WordPress Environment**: Ensure WordPress is installed and configured.
- **Advanced Custom Fields (ACF)**: Required for managing user data.
- **PHP Extensions**: Ensure required PHP extensions, such as GD or Imagick for QR code generation, are installed.

## How It Works

### Core Functions

1. **User Management**:
   - `addUserToAllowedUsers`: Adds a user to the ACF-managed allowed users list.
   - `removeUserFromCustomTable`: Deletes a user from the custom database table.

2. **Email Notifications**:
   - `sendEmailToUser`: Sends an email to the user with credentials or recovery details.
   - `isEmailSent`: Checks if an email has already been sent to a user.
   - `markEmailAsSent`: Marks a user's email as sent in the ACF field.

3. **QR Code Generation**:
   - `generateAndSaveQrCode`: Creates and stores a QR code for invite links.
   - `addImageToMediaLibrary`: Adds generated QR code images to the WordPress media library.

4. **Authentication**:
   - `setAuthCookie`: Sets an authentication cookie for a user.
   - `handleInviteIdAuth`: Handles authentication via invite links.

5. **ACF Integration**:
   - `processAllowedUsersForm`: Processes changes to the allowed users list.
   - `processAllowedUsersInvite`: Processes changes to the invite-based user list.

### Workflow

1. **User Registration**:
   - Users submit a registration form via AJAX.
   - User data is validated and stored in the custom database table.
   - Credentials are sent to the user via email.

2. **Invite-Based Authentication**:
   - An invite link with an ID is sent to the user.
   - Upon clicking the link, a QR code is generated and authenticated.
   - Users are redirected to the appropriate page upon successful authentication.

3. **User Management with ACF**:
   - Admins manage allowed users via the ACF options page.
   - The system synchronizes ACF data with the custom database table.

## Code Highlights

- **Security**:
  - Sanitization of user inputs.
  - Prepared statements for database queries.
  - Secure token generation for cookies and invite links.

- **Extendability**:
  - Modular design with reusable private methods.
  - Easy integration with other plugins or custom themes.

- **Error Handling**:
  - Exceptions are logged for critical processes like QR code generation.


## Notes

- This code is intended for demonstration purposes and may require adjustments for production use.
- Always test thoroughly in a staging environment before deploying.


