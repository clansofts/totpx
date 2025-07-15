use crate::cqrs::event_store::{EventStore, EventStoreError};
use crate::cqrs::{CommandEnvelope, EventEnvelope, UserCommand, UserEvent, UserProjection};
use crate::db::AppState;
use crate::models::{SigninParams, SignupParams, User};
use crate::response::{GenOtpResponse, UserData, UserResponse};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
};
use base32;

use serde::{Deserialize, Serialize};
use serde_json::json;
use surrealdb::{Datetime, opt::auth::Record};
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("User already exists: {0}")]
    UserExists(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("OTP error: {0}")]
    OtpError(String),
    #[error("Token invalid: {0}")]
    TokenInvalid(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Event store error: {0}")]
    EventStoreError(String),
}

impl From<surrealdb::Error> for CommandError {
    fn from(err: surrealdb::Error) -> Self {
        CommandError::DatabaseError(err.to_string())
    }
}

impl From<EventStoreError> for CommandError {
    fn from(err: EventStoreError) -> Self {
        CommandError::EventStoreError(err.to_string())
    }
}

impl IntoResponse for CommandError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            CommandError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            CommandError::UserExists(msg) => (StatusCode::CONFLICT, msg),
            CommandError::UserNotFound(msg) => (StatusCode::NOT_FOUND, msg),
            CommandError::OtpError(msg) => (StatusCode::BAD_REQUEST, msg),
            CommandError::TokenInvalid(msg) => (StatusCode::FORBIDDEN, msg),
            CommandError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            CommandError::EventStoreError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let error_response = json!({
            "status": "fail",
            "message": message
        });

        (status, Json(error_response)).into_response()
    }
}

/// Command Handler responsible for processing commands and generating events
pub struct CommandHandler {
    pub event_store: EventStore,
    pub projection: UserProjection,
    pub db: AppState,
}

impl CommandHandler {
    pub fn new(db: AppState) -> Self {
        let event_store = EventStore::new(db.clone());
        let projection = UserProjection::new(db.clone());

        Self {
            event_store,
            projection,
            db,
        }
    }

    /// Process a command and return the result
    pub async fn handle_command(
        &self,
        command: CommandEnvelope,
    ) -> Result<CommandResult, CommandError> {
        match command.command_data {
            UserCommand::RegisterUser {
                name,
                email,
                password,
            } => {
                self.handle_register_user(command.aggregate_id, name, email, password)
                    .await
            }
            UserCommand::LoginUser { email, password } => {
                self.handle_login_user(command.aggregate_id, email, password)
                    .await
            }
            UserCommand::GenerateOtp { email, user_id } => {
                self.handle_generate_otp(command.aggregate_id, email, user_id)
                    .await
            }
            UserCommand::VerifyOtp { user_id, token } => {
                self.handle_verify_otp(command.aggregate_id, user_id, token)
                    .await
            }
            UserCommand::ValidateOtp { user_id, token } => {
                self.handle_validate_otp(command.aggregate_id, user_id, token)
                    .await
            }
            UserCommand::DisableOtp { user_id } => {
                self.handle_disable_otp(command.aggregate_id, user_id).await
            }
        }
    }

    async fn handle_register_user(
        &self,
        _aggregate_id: String,
        name: String,
        email: String,
        password: String,
    ) -> Result<CommandResult, CommandError> {
        println!(
            "Handling registration for user: {} name {}",
            email.clone(),
            name.clone()
        );
        // Check if user already exists in read model
        let existing_users: Vec<User> = self.db.db.select("mcp_auth").await?;

        for user in existing_users.iter() {
            if user.username == email.to_lowercase() {
                return Err(CommandError::UserExists(format!(
                    "User with email: {} already exists",
                    user.username
                )));
            }
        }

        let user_id = Uuid::new_v4().to_string();

        // Create and save the event
        let event = EventEnvelope::new(
            user_id.clone(),
            UserEvent::UserRegistered {
                user_id: user_id.clone(),
                username: email.to_lowercase(),
                secret: password.clone(),
                category: "Root".to_string(),
                stakeholder: "".to_string(),
                status: name,
            },
        );

        // println!("Registering user: {:?}", event.clone());

        // Save to event store
        self.event_store.save_event(event.clone()).await?;

        // Update projection
        // self.projection.handle_event(&event).await?;

        // Also register with SurrealDB auth system
        let _jwt = self
            .db
            .db
            .signup(Record {
                access: "mcp_authx",
                namespace: "malipo",
                database: "eventors",
                params: SignupParams {
                    username: email.as_str(),
                    secret: password.as_str(),
                    category: "App/Individual/Organization",
                    stakeholder: "",
                    status: "New",
                },
            })
            .await
            .map_err(|_| CommandError::InternalError("Failed to signup user".to_string()))?;

        Ok(CommandResult::UserRegistered {
            message: "Registered successfully, please login".to_string(),
        })
    }

    async fn handle_login_user(
        &self,
        _aggregate_id: String,
        email: String,
        password: String,
    ) -> Result<CommandResult, CommandError> {
        println!(
            "Handling login for user: {} password {}",
            email.clone(),
            password.clone()
        );
        // Authenticate with SurrealDB
        let _token = self
            .db
            .db
            .signin(Record {
                access: "mcp_authx",
                namespace: "malipo",
                database: "eventors",
                params: SigninParams {
                    username: email.as_str(),
                    secret: password.as_str(),
                },
            })
            .await?;

        // Query the read model for user data
        let mut result = self
            .db
            .db
            .query("select * from only mcp_auth where username = $username")
            .bind(("username", email.clone().to_lowercase()))
            .await?;

        println!("Login query result: {:?}", result).clone();

        let user: Option<User> = result.take(0)?;
        let user = user.ok_or_else(|| CommandError::UserNotFound("User not found".to_string()))?;

        // Create login event
        let event = EventEnvelope::new(
            user.id.as_ref().map_or("".to_string(), |id| id.to_string()),
            UserEvent::UserLoggedIn {
                user_id: user.id.as_ref().map_or("".to_string(), |id| id.to_string()),
                username: email,
                timestamp: Datetime::default(),
            },
        );

        // Save login event
        self.event_store.save_event(event.clone()).await?;
        self.projection.handle_event(&event).await?;

        Ok(CommandResult::UserLoggedIn {
            user_response: UserResponse {
                status: "success".to_string(),
                user: Self::user_to_response(&user),
            },
        })
    }

    async fn handle_generate_otp(
        &self,
        _aggregate_id: String,
        email: String,
        user_id: String,
    ) -> Result<CommandResult, CommandError> {
        println!(
            "Generating OTP for user: {}, {} {}",
            email, user_id, _aggregate_id
        );
        // Get user from read model
        let user: Option<User> = self.db.db.select(("mcp_auth", &email)).await?;
        let user = user.ok_or_else(|| CommandError::UserNotFound("User not found".to_string()))?;

        let otp_url = user.otp_auth_url.clone().unwrap_or_default();
        let base_secret = user.otp_secret.clone().unwrap_or_default();

        // Check if OTP is already setup
        if !otp_url.is_empty() && !base_secret.is_empty() {
            println!("User already has OTP setup: {:?}", user.clone());
            return Err(CommandError::OtpError("User 2FA already Setup".to_string()));
        }

        // println!("User X found: {:?}", user.clone());
        // Generate OTP secret (temporarily using a fixed secret for compilation)
        // TODO: Fix random generation for production
        let data_byte = [1u8; 21]; // Fixed for now
        // use getrandom::getrandom;
        // getrandom(&mut data_byte).map_err(|e| CommandError::OtpError(format!("Random generation failed: {}", e)))?;
        let base32_string =
            base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &data_byte);

        // println!("Base32 OTP secret: {}", base32_string.clone());
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(base32_string).to_bytes().unwrap(),
        )
        .unwrap();

        let otp_base32 = totp.get_secret_base32();
        let issuer = "Malipo-Popote-Solutions";
        let otp_auth_url =
            format!("otpauth://totp/{issuer}:{email}?secret={otp_base32}&issuer={issuer}");

        // Create and save event
        let event = EventEnvelope::new(
            user_id.clone(),
            UserEvent::OtpSecretGenerated {
                user_id: user_id.clone(),
                email: email.clone(),
                otp_secret: otp_base32.clone(),
                otp_auth_url: otp_auth_url.clone(),
            },
        );

        // println!("Generating OTP for user: {:?}", event.clone());

        self.event_store.save_event(event.clone()).await?;
        self.projection.handle_event(&event).await?;

        Ok(CommandResult::OtpGenerated {
            response: GenOtpResponse {
                base32_secret: otp_base32,
                otp_auth_url,
            },
        })
    }

    async fn handle_verify_otp(
        &self,
        _aggregate_id: String,
        user_id: String,
        token: String,
    ) -> Result<CommandResult, CommandError> {
        // Get user from read model
        let user: Option<User> = self.db.db.select(("mcp_auth", &user_id)).await?;
        let user = user.ok_or_else(|| CommandError::UserNotFound("User not found".to_string()))?;

        let otp_base32 = user
            .otp_secret
            .clone()
            .ok_or_else(|| CommandError::OtpError("OTP not generated for this user".to_string()))?;

        // Validate token
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(otp_base32).to_bytes().unwrap(),
        )
        .unwrap();

        let is_valid = totp.check_current(&token).unwrap();

        if !is_valid {
            return Err(CommandError::TokenInvalid(
                "Token is invalid or user doesn't exist".to_string(),
            ));
        }

        // Create and save event
        let event = EventEnvelope::new(
            user_id.clone(),
            UserEvent::OtpVerified {
                user_id: user_id.clone(),
                otp_enabled: true,
                otp_verified: true,
            },
        );

        self.event_store.save_event(event.clone()).await?;
        self.projection.handle_event(&event).await?;

        // Get updated user
        let updated_user: Option<User> = self.db.db.select(("mcp_auth", &user_id)).await?;
        let updated_user = updated_user.unwrap_or(user);

        Ok(CommandResult::OtpVerified {
            user_data: Self::user_to_response(&updated_user),
        })
    }

    async fn handle_validate_otp(
        &self,
        _aggregate_id: String,
        user_id: String,
        token: String,
    ) -> Result<CommandResult, CommandError> {
        // Get user from read model
        let user: Option<User> = self.db.db.select(("mcp_auth", &user_id)).await?;
        let user = user.ok_or_else(|| CommandError::UserNotFound("User not found".to_string()))?;

        if !user.otp_enabled.unwrap_or(false) {
            return Err(CommandError::TokenInvalid("2FA not enabled".to_string()));
        }

        let otp_base32 = user
            .otp_secret
            .ok_or_else(|| CommandError::OtpError("OTP secret not found".to_string()))?;

        // Validate token
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(otp_base32).to_bytes().unwrap(),
        )
        .unwrap();

        let is_valid = totp.check_current(&token).unwrap();

        // Create validation event (for audit purposes)
        let event = EventEnvelope::new(
            user_id.clone(),
            UserEvent::OtpValidated {
                user_id: user_id.clone(),
                token: token.clone(),
                is_valid,
            },
        );

        self.event_store.save_event(event).await?;

        if !is_valid {
            return Err(CommandError::TokenInvalid(
                "Token is invalid or user doesn't exist".to_string(),
            ));
        }

        Ok(CommandResult::OtpValidated { is_valid: true })
    }

    async fn handle_disable_otp(
        &self,
        _aggregate_id: String,
        user_id: String,
    ) -> Result<CommandResult, CommandError> {
        // Get user from read model
        let user: Option<User> = self.db.db.select(("mcp_auth", &user_id)).await?;
        let _user = user.ok_or_else(|| CommandError::UserNotFound("User not found".to_string()))?;

        // Create and save event
        let event = EventEnvelope::new(
            user_id.clone(),
            UserEvent::OtpDisabled {
                user_id: user_id.clone(),
            },
        );

        self.event_store.save_event(event.clone()).await?;
        self.projection.handle_event(&event).await?;

        // Get updated user
        let updated_user: Option<User> = self.db.db.select(("mcp_auth", &user_id)).await?;
        let updated_user = updated_user
            .ok_or_else(|| CommandError::UserNotFound("User not found after update".to_string()))?;

        Ok(CommandResult::OtpDisabled {
            user_data: Self::user_to_response(&updated_user),
        })
    }

    fn user_to_response(user: &User) -> UserData {
        UserData {
            id: user.id.as_ref().map_or("".to_string(), |id| id.to_string()),
            username: user.username.to_owned(),
            secret: user.secret.to_owned(),
            otp_auth_url: user.otp_auth_url.to_owned(),
            otp_secret: user.otp_secret.to_owned(),
            otp_enabled: user.otp_enabled.unwrap_or(false),
            otp_verified: user.otp_verified.unwrap_or(false),
            stamp: user
                .stamp
                .as_ref()
                .map_or("".to_string(), |s| s.to_string()),
            changed: user
                .changed
                .as_ref()
                .map_or("".to_string(), |c| c.to_string()),
            category: user.category.to_owned(),
            stakeholder: user.stakeholder.to_owned(),
            status: user.status.to_owned(),
            expired: user.expired.unwrap_or(false),
            verified: user.verified.unwrap_or(false),
        }
    }
}

/// Command execution results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result_type")]
pub enum CommandResult {
    UserRegistered { message: String },
    UserLoggedIn { user_response: UserResponse },
    OtpGenerated { response: GenOtpResponse },
    OtpVerified { user_data: UserData },
    OtpValidated { is_valid: bool },
    OtpDisabled { user_data: UserData },
}
