# Authentication Overview

This document provides an overview of the authentication system implemented in the project using FastAPI.

## API Endpoints

The authentication-related API endpoints are defined in `backend/app/api/routes/auth.py`. These endpoints handle various authentication and user management tasks:

- **`/register`**: Registers a new user by hashing their password and assigning a default "viewer" role. It checks for existing usernames or emails to prevent duplicates.

- **`/login`**: Authenticates a user using their username and password. Upon successful authentication, it issues both an access token (short-lived) and a refresh token (long-lived).

- **`/refresh`**: Issues a new access token using a valid refresh token. It verifies the refresh token's validity and existence in the database.

- **`/logout`**: Invalidates the refresh token, effectively logging the user out.

- **`/me`**: Retrieves the current user's information, requiring authentication.

- **Admin Routes**: Includes endpoints for listing users, getting user details, activating/deactivating users, assigning roles, and deleting users. These routes require admin privileges.

## Core Authentication Logic

The core authentication logic is implemented in `backend/app/core/auth.py` and includes:

- **Password Management**:
  - `verify_password`: Compares a plain password with a hashed password using bcrypt.
  - `get_password_hash`: Hashes a plain password using bcrypt.

- **Token Management**:
  - `create_access_token`: Generates a JWT access token with an expiration time, signed using a secret key and the HS256 algorithm.

- **User Authentication**:
  - `get_current_user`: Retrieves the current user based on the JWT token provided. It decodes the token, extracts the username, and fetches the user from the database.

- **Admin Verification**:
  - `verify_admin`: Ensures that the current user has an "admin" role, raising an exception if not.

## Security

The authentication system uses JWT tokens for secure user sessions. Access tokens are short-lived, while refresh tokens are stored in the database for extended sessions. Passwords are securely hashed before storage to ensure user data protection.

This system is designed to manage user sessions and permissions securely, leveraging FastAPI's features for dependency injection and user verification.
