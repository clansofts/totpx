# TOTPX - Two-Factor Authentication (2FA) REST API

A secure and lightweight REST API built with Rust and Axum that implements Time-based One-Time Password (TOTP) authentication for enhanced security.

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
- **Axum** - High-performance web framework for Rust
- **SurrealDB** - Multi-model database for modern applications
- **TOTP-RS** - TOTP (Time-based One-Time Password) implementation
- **Chrono** - Date and time handling
- **Serde** - Serialization/deserialization framework
- **UUID** - Unique identifier generation
- **Base32** - Base32 encoding for TOTP secrets
- **Tower-HTTP** - HTTP middleware for Axum

## 📋 Prerequisites

- Rust 1.70+ and Cargo (using Rust 2024 edition)
- SurrealDB server running on `0.0.0.0:5555`
- A TOTP authenticator app (Google Authenticator, Authy, etc.)

## 🚀 Quick Start

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/clansofts/totpx.git
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
export RUST_LOG=debug
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
├── main.rs              # Application entry point and server configuration
├── api.rs               # Original API route handlers (legacy)
├── cqrs_api.rs          # CQRS-based API route handlers
├── services.rs          # Original business logic (legacy)
├── cqrs_service.rs      # CQRS service layer
├── models.rs            # Data models and application state
├── response.rs          # Response structures
├── db.rs                # Database connection utilities
└── cqrs/                # CQRS implementation modules
    ├── mod.rs           # CQRS module exports
    ├── commands.rs      # Command definitions
    ├── events.rs        # Event definitions
    ├── queries.rs       # Query definitions
    ├── command_handler.rs # Command processing logic
    ├── query_handler.rs   # Query processing logic
    ├── event_store.rs     # Event store implementation
    └── projections.rs     # Read model projections
increment.surql          # SurrealDB functions for counter and serial generation
```

### Key Components

- **main.rs**: Application entry point with server configuration
- **cqrs_api.rs**: HTTP endpoints with CQRS pattern (commands and queries)
- **cqrs_service.rs**: CQRS service layer coordinating commands and queries  
- **command_handler.rs**: Processes commands and generates events
- **query_handler.rs**: Handles read operations from optimized models
- **event_store.rs**: Persists and retrieves domain events (`events_store` table)
- **projections.rs**: Updates read models from events (`mcp_auth` table)
- **models.rs**: Data structures and application state management
- **response.rs**: Response DTOs and data transformation
- **AppState**: SurrealDB database connection and state management
- **TOTP Integration**: Secure TOTP generation and validation with event sourcing
- **CORS Configuration**: Enabled for `localhost:3000`

## 🏛️ Architecture - CQRS Implementation

The application has been converted to use **CQRS (Command Query Responsibility Segregation)** pattern with event sourcing for enhanced scalability, auditability, and separation of concerns.

### CQRS Components

#### **Command Side (Write Operations)**
- **Event Store (`events_store` table)**: Stores all domain events as the source of truth
- **Command Handlers**: Process commands and generate events
- **Commands**: Represent user intentions (RegisterUser, GenerateOtp, etc.)
- **Events**: Immutable facts about what happened (UserRegistered, OtpGenerated, etc.)

#### **Query Side (Read Operations)**  
- **Read Model (`mcp_auth` table)**: Optimized for queries, built from events
- **Query Handlers**: Handle read operations efficiently
- **Projections**: Update read models when events occur

### Architecture Benefits

- **Scalability**: Read and write sides can scale independently
- **Auditability**: Complete event history for compliance and debugging
- **Performance**: Optimized read models for different query patterns
- **Reliability**: Event sourcing provides natural backup and replay capabilities
- **Flexibility**: Easy to add new read models without affecting write side

### Data Flow

1. **Commands** → **Command Handlers** → **Events** → **Event Store**
2. **Events** → **Projections** → **Read Models** 
3. **Queries** → **Query Handlers** → **Read Models**

### Event Store Schema

```sql
-- Event Store (events_store table)
{
  "event_id": "uuid",
  "aggregate_id": "user_id", 
  "aggregate_type": "User",
  "event_version": 1,
  "event_data": {
    "event_type": "UserRegistered|OtpGenerated|OtpVerified|...",
    // event-specific data
  },
  "timestamp": "2025-07-15T10:00:00Z"
}
```

### Available Commands

- `RegisterUser` - Register a new user account
- `LoginUser` - Authenticate user login
- `GenerateOtp` - Generate TOTP secret for 2FA
- `VerifyOtp` - Verify TOTP token and enable 2FA
- `ValidateOtp` - Validate TOTP token for authentication
- `DisableOtp` - Disable 2FA for user account

### Available Queries

- `GetUserById` - Retrieve user by ID
- `GetUserByEmail` - Find user by email address
- `GetAllUsers` - List all users
- `GetUsersWithOtpEnabled` - List users with 2FA enabled

### New API Endpoints (CQRS)

#### Query Endpoints (Read Operations)
```http
GET /api/users/:user_id          # Get user by ID
GET /api/users                   # Get all users  
GET /api/users/otp-enabled       # Get users with 2FA enabled
GET /api/stats/users             # Get user statistics
```

#### Command Endpoints (Write Operations) 
```http
POST /api/auth/register          # Register user (command)
POST /api/auth/login             # Login user (command)  
POST /api/auth/otp/generate      # Generate OTP (command)
POST /api/auth/otp/verify        # Verify OTP (command)
POST /api/auth/otp/validate      # Validate OTP (command)
POST /api/auth/otp/disable       # Disable OTP (command)
```

### Event Sourcing Benefits

- **Complete Audit Trail**: Every action is recorded as an immutable event
- **Time Travel**: Query system state at any point in history
- **Replay Capability**: Rebuild read models by replaying events
- **Natural Backup**: Event store serves as definitive system backup

## 🚧 Implementation Status

### Current Status
- ✅ **Original Architecture**: Fully functional with traditional layered approach
- 🔄 **CQRS Architecture**: Implementation in progress with the following components:

#### Completed CQRS Components
- ✅ Event definitions and command/query models
- ✅ Event store structure and interface
- ✅ Command and query handler architecture
- ✅ Projection system design
- ✅ CQRS service layer interface

#### In Progress
- 🔄 Type compatibility and serialization fixes
- 🔄 Database operation refinements
- 🔄 Error handling improvements
- 🔄 Integration testing

#### To Switch to CQRS
1. Fix compilation errors in CQRS modules
2. Update main.rs to use `cqrs_api::create_routes()`
3. Run database migrations to set up `events_store` table
4. Test complete CQRS workflow

The application currently runs with the original architecture while the CQRS implementation is being finalized.

### API Layer (`api.rs` / `cqrs_api.rs`)

- Handles HTTP requests and responses
- Input validation and serialization/deserialization
- Axum route handlers and middleware integration
- Maps command/query results to appropriate HTTP responses
- Separates command endpoints (writes) from query endpoints (reads)

### Service Layer (`services.rs` / `cqrs_service.rs`)

- **Command Handlers**: Process commands and generate events
- **Query Handlers**: Handle read operations from optimized read models
- **Event Store**: Persist and retrieve domain events
- **Projections**: Update read models based on events
- TOTP generation and verification logic
- User management operations with full audit trail

### Model Layer (`models.rs`)

- Data structures and schemas for commands, events, and queries
- SurrealDB database configuration and connection
- Event store and read model schemas
- Request/response DTOs

This CQRS architecture provides:

- **Scalability**: Command and query sides scale independently
- **Performance**: Optimized read models for different access patterns
- **Auditability**: Complete event history for compliance and debugging
- **Testability**: Business logic is decoupled from HTTP framework
- **Maintainability**: Clear separation between write and read operations
- **Reusability**: Service layer can be used by different presentation layers
- **Reliability**: Event sourcing provides natural backup and replay capabilities
- **Flexibility**: Easy to add new projections without affecting existing code

## ⚙️ Configuration

### Database Configuration

The application connects to a remote SurrealDB instance with the following settings:

- **Address**: `0.0.0.0:5555`
- **Username**: `root`
- **Password**: `@273gha732hjaaa`
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
4. **Rate Limiting**: Implement rate limiting middleware with Tower
5. **Logging**: Enhanced logging and monitoring with structured tracing
6. **Environment Configuration**: Use environment variables for configuration
7. **HTTPS**: Deploy with TLS/SSL certificates
8. **Axum Middleware**: Leverage Tower ecosystem for additional middleware

## 📝 Dependencies

```toml
axum = "0.8.4"            # Web framework
tower = "0.5.2"           # Middleware and utilities for async code
tower-http = "0.6.6"      # HTTP middleware (with cors and trace features)
base32 = "0.5.1"          # Base32 encoding
chrono = "0.4.41"         # Date/time handling (with serde support)
rand = "0.9.1"            # Random number generation
serde = "1.0.219"         # Serialization (with derive features)
serde_json = "1.0.140"    # JSON serialization
surrealdb = "2.3.7"       # SurrealDB client (with kv-mem features)
thiserror = "2.0.12"      # Error handling
tokio = "1.44.0"          # Async runtime (with macros and rt-multi-thread)
totp-rs = "5.7.0"         # TOTP implementation
uuid = "1.17.0"           # UUID generation (with v4 support)
tracing = "0.1"           # Application-level tracing
tracing-subscriber = "0.3" # Tracing subscriber for logging
```

## 📄 License

[Add your license information here]

## 🤝 Contributing

[Add contribution guidelines here]

## 📧 Contact

[Add contact information here]

---

**Note**: This is a development/demonstration implementation using Axum web framework. For production use, implement proper password hashing, persistent storage, and additional security measures.
