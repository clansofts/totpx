# TOTPX - Two-Factor Authentication (2FA) REST API

A secure and lightweight REST API built with Rust and Actix-web that implements Time-based One-Time Password (TOTP) authentication for enhanced security.

## 🚀 Features

- **User Registration & Authentication**: Secure user registration and login system
- **TOTP Generation**: Generate secure TOTP secrets and authentication URLs
- **2FA Verification**: Verify TOTP tokens for authentication
- **2FA Validation**: Validate TOTP tokens for ongoing authentication
- **2FA Management**: Enable/disable 2FA for user accounts
- **CORS Support**: Cross-origin resource sharing enabled for web applications
- **SurrealDB Storage**: Persistent data storage with SurrealDB remote database via WebSocket

## 🛠️ Tech Stack

- **Rust** - Systems programming language for performance and safety
- **Actix-web** - High-performance web framework for Rust
- **SurrealDB** - Multi-model database for modern applications
- **TOTP-RS** - TOTP (Time-based One-Time Password) implementation
- **Chrono** - Date and time handling
- **Serde** - Serialization/deserialization framework
- **UUID** - Unique identifier generation
- **Base32** - Base32 encoding for TOTP secrets

## 📋 Prerequisites

- Rust 1.70+ and Cargo (using Rust 2024 edition)
- SurrealDB server running on `0.0.0.0:5555`
- A TOTP authenticator app (Google Authenticator, Authy, etc.)

## 🚀 Quick Start

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd totpx
   ```

2. **Start SurrealDB server**

   ```bash
   # Install SurrealDB if not already installed
   # curl --proto '=https' --tlsv1.2 -sSf https://install.surrealdb.com | sh
   
   # Start SurrealDB server
   surreal start --bind 0.0.0.0:5555 --user root --pass '@Cr34f1n1ty'
   ```

3. **Build the project**

   ```bash
   cargo build
   ```

4. **Run the server**

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
    "id": "user:uuid-string",
    "category": "user_category",
    "username": "john@example.com",
    "status": "active",
    "stakeholder": "organization_name",
    "expired": false,
    "verified": true,
    "otp_enabled": false,
    "otp_verified": false,
    "otp_secret": null,
    "otp_auth_url": null,
    "stamp": "2025-07-12T10:00:00Z",
    "changed": "2025-07-12T10:00:00Z"
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
    "id": "user:uuid-string",
    "category": "user_category", 
    "username": "john@example.com",
    "status": "active",
    "stakeholder": "organization_name",
    "expired": false,
    "verified": true,
    "otp_enabled": true,
    "otp_verified": true,
    "otp_secret": "JBSWY3DPEHPK3PXP",
    "otp_auth_url": "otpauth://totp/...",
    "stamp": "2025-07-12T10:00:00Z",
    "changed": "2025-07-12T10:00:00Z"
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
    "id": "user:uuid-string",
    "category": "user_category",
    "username": "john@example.com", 
    "status": "active",
    "stakeholder": "organization_name",
    "expired": false,
    "verified": true,
    "otp_enabled": false,
    "otp_verified": false,
    "otp_secret": null,
    "otp_auth_url": null,
    "stamp": "2025-07-12T10:00:00Z",
    "changed": "2025-07-12T10:00:00Z"
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
├── api.rs           # API route handlers and Actix-web layer
├── services.rs      # Business logic and service layer
├── models.rs        # Data models and application state
├── response.rs      # Response structures
└── increment.surql  # SurrealDB functions for counter and serial generation
```

### Key Components

- **main.rs**: Application entry point with server configuration
- **api.rs**: HTTP endpoints and request/response handling (Actix-web layer)
- **services.rs**: Business logic, data validation, and core functionality
- **models.rs**: Data structures and application state management
- **response.rs**: Response DTOs and data transformation
- **AppState**: SurrealDB database connection and state management
- **UserService**: Service layer handling all business operations
- **TOTP Integration**: Secure TOTP generation and validation
- **CORS Configuration**: Enabled for `localhost:3000`

## 🏛️ Architecture

The application follows a layered architecture pattern with clear separation of concerns:

### API Layer (`api.rs`)

- Handles HTTP requests and responses
- Input validation and serialization/deserialization
- Actix-web route handlers and middleware integration
- Maps service results to appropriate HTTP responses

### Service Layer (`services.rs`)

- Contains all business logic and rules
- Data processing and validation
- TOTP generation and verification logic
- User management operations
- Returns structured results that can be easily mapped to HTTP responses

### Model Layer (`models.rs`)

- Data structures and schemas
- SurrealDB database configuration and connection
- Request/response DTOs

This architecture provides:

- **Testability**: Business logic is decoupled from HTTP framework
- **Maintainability**: Clear separation between web layer and business logic
- **Reusability**: Service layer can be used by different presentation layers
- **Scalability**: Easy to extend with additional services or API versions

## ⚙️ Configuration

### Database Configuration

The application connects to a remote SurrealDB instance with the following settings:

- **Address**: `0.0.0.0:5555`
- **Username**: `root`
- **Password**: `@832ybdsb2u272`
- **Namespace**: `malipo`
- **Database**: `eventors`

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
- **SurrealDB Storage**: Remote database connection (ensure proper network security and access controls)
- **HTTPS**: Use HTTPS in production environments
- **Rate Limiting**: Consider implementing rate limiting for authentication endpoints

## 🚀 Production Deployment

For production use, consider:

1. **Database Security**: Secure SurrealDB connection with proper authentication and network security
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
chrono = "0.4.41"         # Date/time handling (with serde support)
env_logger = "0.11.8"     # Logging
rand = "0.9.1"            # Random number generation
serde = "1.0.219"         # Serialization (with derive features)
serde_json = "1.0.140"    # JSON serialization
surrealdb = "2.3.7"       # SurrealDB client (with kv-mem features)
thiserror = "2.0.12"      # Error handling
tokio = "1.44.0"          # Async runtime (with macros and rt-multi-thread)
totp-rs = "5.7.0"         # TOTP implementation
uuid = "1.17.0"           # UUID generation (with v4 support)
```

## 📄 License

[Add your license information here]

## 🤝 Contributing

[Add contribution guidelines here]

## 📧 Contact

[Add contact information here]

---

**Note**: This is a development/demonstration implementation. For production use, implement proper password hashing, persistent storage, and additional security measures.
