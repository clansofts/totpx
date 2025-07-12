# TOTPX - Two-Factor Authentication (2FA) REST API

A secure and lightweight REST API built with Rust and Actix-web that implements Time-based One-Time Password (TOTP) authentication for enhanced security.

## 🚀 Features

- **User Registration & Authentication**: Secure user registration and login system
- **TOTP Generation**: Generate secure TOTP secrets and authentication URLs
- **2FA Verification**: Verify TOTP tokens for authentication
- **2FA Validation**: Validate TOTP tokens for ongoing authentication
- **2FA Management**: Enable/disable 2FA for user accounts
- **CORS Support**: Cross-origin resource sharing enabled for web applications
- **In-memory Storage**: Simple in-memory user data storage (suitable for development/testing)

## 🛠️ Tech Stack

- **Rust** - Systems programming language for performance and safety
- **Actix-web** - High-performance web framework for Rust
- **TOTP-RS** - TOTP (Time-based One-Time Password) implementation
- **Chrono** - Date and time handling
- **Serde** - Serialization/deserialization framework
- **UUID** - Unique identifier generation
- **Base32** - Base32 encoding for TOTP secrets

## 📋 Prerequisites

- Rust 1.70+ and Cargo
- A TOTP authenticator app (Google Authenticator, Authy, etc.)

## 🚀 Quick Start

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd totpx
   ```

2. **Build the project**

   ```bash
   cargo build
   ```

3. **Run the server**

   ```bash
   cargo run
   ```

The server will start on `http://127.0.0.1:8000`

### Environment Setup

Enable logging (optional):

```bash
export RUST_LOG=actix_web=info
```

## 📚 API Documentation

### Base URL

```text
http://127.0.0.1:8000/api
```

### Endpoints

#### Health Check

```http
GET /api/healthchecker
```

**Response:**

```json
{
  "status": "success",
  "message": "How to Implement Two-Factor Authentication (2FA) in Rust"
}
```

#### User Registration

```http
POST /api/auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "secure_password"
}
```

**Success Response (200):**

```json
{
  "status": "success",
  "message": "Registered successfully, please login"
}
```

**Error Response (409):**

```json
{
  "status": "fail",
  "message": "User with email: john@example.com already exists"
}
```

#### User Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "secure_password"
}
```

**Success Response (200):**

```json
{
  "status": "success",
  "user": {
    "id": "uuid-string",
    "email": "john@example.com",
    "name": "John Doe",
    "otp_enabled": false,
    "otp_verified": false,
    "otp_base32": null,
    "otp_auth_url": null,
    "createdAt": "2025-07-12T10:00:00Z",
    "updatedAt": "2025-07-12T10:00:00Z"
  }
}
```

#### Generate TOTP Secret

```http
POST /api/auth/otp/generate
Content-Type: application/json

{
  "email": "john@example.com",
  "user_id": "uuid-string"
}
```

**Success Response (200):**

```json
{
  "base32": "JBSWY3DPEHPK3PXP",
  "otpauth_url": "otpauth://totp/Malipo%20Popote%20Solutions:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Malipo%20Popote%20Solutions"
}
```

#### Verify TOTP Token (Enable 2FA)

```http
POST /api/auth/otp/verify
Content-Type: application/json

{
  "user_id": "uuid-string",
  "token": "123456"
}
```

**Success Response (200):**

```json
{
  "otp_verified": true,
  "user": {
    "id": "uuid-string",
    "email": "john@example.com",
    "name": "John Doe",
    "otp_enabled": true,
    "otp_verified": true,
    "otp_base32": "JBSWY3DPEHPK3PXP",
    "otp_auth_url": "otpauth://totp/...",
    "createdAt": "2025-07-12T10:00:00Z",
    "updatedAt": "2025-07-12T10:00:00Z"
  }
}
```

#### Validate TOTP Token

```http
POST /api/auth/otp/validate
Content-Type: application/json

{
  "user_id": "uuid-string",
  "token": "123456"
}
```

**Success Response (200):**

```json
{
  "otp_valid": true
}
```

#### Disable 2FA

```http
POST /api/auth/otp/disable
Content-Type: application/json

{
  "user_id": "uuid-string"
}
```

**Success Response (200):**

```json
{
  "user": {
    "id": "uuid-string",
    "email": "john@example.com",
    "name": "John Doe",
    "otp_enabled": false,
    "otp_verified": false,
    "otp_base32": null,
    "otp_auth_url": null,
    "createdAt": "2025-07-12T10:00:00Z",
    "updatedAt": "2025-07-12T10:00:00Z"
  },
  "otp_disabled": true
}
```

## 🔐 2FA Setup Workflow

1. **Register a user** using `/auth/register`
2. **Login** to get user details using `/auth/login`
3. **Generate TOTP secret** using `/auth/otp/generate`
4. **Scan the QR code** or manually enter the secret in your authenticator app
5. **Verify the token** using `/auth/otp/verify` to enable 2FA
6. **Use `/auth/otp/validate`** for subsequent authentications

## 🏗️ Project Structure

```text
src/
├── main.rs          # Application entry point and server configuration
├── models.rs        # Data models and application state
├── response.rs      # Response structures
└── service.rs       # API route handlers and business logic
```

### Key Components

- **AppState**: In-memory storage for user data
- **User**: Core user model with 2FA fields
- **TOTP Integration**: Secure TOTP generation and validation
- **CORS Configuration**: Enabled for `localhost:3000`

## ⚙️ Configuration

### CORS Settings

The API is configured to accept requests from:

- `http://localhost:3000`

### TOTP Configuration

- **Algorithm**: SHA1
- **Digits**: 6
- **Step**: 30 seconds
- **Issuer**: "Malipo Popote Solutions"

## 🧪 Testing

Test the API using curl, Postman, or any HTTP client:

```bash
# Health check
curl http://127.0.0.1:8000/api/healthchecker

# Register user
curl -X POST http://127.0.0.1:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@example.com","password":"password123"}'
```

## 🔒 Security Considerations

- **Password Security**: Passwords are stored in plain text (implement hashing for production)
- **TOTP Secrets**: Securely generated using cryptographic randomness
- **In-Memory Storage**: Data is lost on restart (implement persistent storage for production)
- **HTTPS**: Use HTTPS in production environments
- **Rate Limiting**: Consider implementing rate limiting for authentication endpoints

## 🚀 Production Deployment

For production use, consider:

1. **Database Integration**: Replace in-memory storage with a proper database
2. **Password Hashing**: Implement bcrypt or similar for password security
3. **JWT Tokens**: Add JWT-based authentication
4. **Rate Limiting**: Implement rate limiting middleware
5. **Logging**: Enhanced logging and monitoring
6. **Environment Configuration**: Use environment variables for configuration
7. **HTTPS**: Deploy with TLS/SSL certificates

## 📝 Dependencies

```toml
actix-cors = "0.7.1"      # CORS middleware
actix-web = "4.11.0"      # Web framework
base32 = "0.5.1"          # Base32 encoding
chrono = "0.4.41"         # Date/time handling
env_logger = "0.11.8"     # Logging
rand = "0.9.1"            # Random number generation
serde = "1.0.219"         # Serialization
serde_json = "1.0.140"    # JSON serialization
totp-rs = "5.7.0"         # TOTP implementation
uuid = "1.17.0"           # UUID generation
```

## 📄 License

[Add your license information here]

## 🤝 Contributing

[Add contribution guidelines here]

## 📧 Contact

[Add contact information here]

---

**Note**: This is a development/demonstration implementation. For production use, implement proper password hashing, persistent storage, and additional security measures.
