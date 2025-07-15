use crate::cqrs::{
    CommandEnvelope, CommandHandler, CommandResult, QueryHandler, QueryResult, UserCommand,
    UserQuery,
};
use crate::db::AppState;
use crate::models::{
    DisableOTPSchema, GenerateOTPSchema, UserLoginSchema, UserRegisterSchema, VerifyOTPSchema,
};
use crate::response::{UserData, UserResponse};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde_json::json;
use surrealdb::Error;
use uuid::Uuid;

/// CQRS-based User Service that separates command and query responsibilities
pub struct CqrsUserService {
    command_handler: CommandHandler,
    query_handler: QueryHandler,
}

impl CqrsUserService {
    pub fn new(db: AppState) -> Self {
        Self {
            command_handler: CommandHandler::new(db.clone()),
            query_handler: QueryHandler::new(db),
        }
    }

    /// Register a new user (Command)
    pub async fn register_user(
        &self,
        body: &UserRegisterSchema,
    ) -> Result<String, impl IntoResponse> {
        let aggregate_id = Uuid::new_v4().to_string();
        let command = CommandEnvelope::new(
            aggregate_id,
            UserCommand::RegisterUser {
                name: body.name.clone(),
                email: body.email.clone(),
                password: body.password.clone(),
            },
        );

        match self.command_handler.handle_command(command).await {
            Ok(CommandResult::UserRegistered { message }) => Ok(message),
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected command result"})),
            )),
            Err(err) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command failed: {}", err)})),
            )),
        }
    }

    /// Login user (Command with Query)
    pub async fn login_user(&self, body: &UserLoginSchema) -> Result<UserResponse, Error> {
        let aggregate_id = Uuid::new_v4().to_string();
        let command = CommandEnvelope::new(
            aggregate_id,
            UserCommand::LoginUser {
                email: body.email.clone(),
                password: body.password.clone(),
            },
        );

        match self.command_handler.handle_command(command).await {
            Ok(CommandResult::UserLoggedIn { user_response }) => Ok(user_response),
            Ok(_) => Err(surrealdb::Error::Api(surrealdb::error::Api::InvalidParams(
                "Unexpected command result".to_string(),
            ))),
            Err(_) => Err(surrealdb::Error::Api(surrealdb::error::Api::InvalidParams(
                "Login failed".to_string(),
            ))),
        }
    }

    /// Generate OTP (Command)
    pub async fn generate_otp(
        &self,
        body: &GenerateOTPSchema,
    ) -> Result<(String, String), impl IntoResponse> {
        let command = CommandEnvelope::new(
            body.user_id.clone(),
            UserCommand::GenerateOtp {
                email: body.email.clone(),
                user_id: body.user_id.clone(),
            },
        );

        match self.command_handler.handle_command(command).await {
            Ok(CommandResult::OtpGenerated { response }) => {
                Ok((response.base32_secret, response.otp_auth_url))
            }
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected command result"})),
            )),
            Err(err) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command failed: {}", err)})),
            )),
        }
    }

    /// Verify OTP (Command)
    pub async fn verify_otp(&self, body: &VerifyOTPSchema) -> Result<UserData, impl IntoResponse> {
        let command = CommandEnvelope::new(
            body.user_id.clone(),
            UserCommand::VerifyOtp {
                user_id: body.user_id.clone(),
                token: body.token.clone(),
            },
        );

        match self.command_handler.handle_command(command).await {
            Ok(CommandResult::OtpVerified { user_data }) => Ok(user_data),
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected command result"})),
            )),
            Err(err) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command failed: {}", err)})),
            )),
        }
    }

    /// Validate OTP (Command)
    pub async fn validate_otp(&self, body: &VerifyOTPSchema) -> Result<bool, impl IntoResponse> {
        let command = CommandEnvelope::new(
            body.user_id.clone(),
            UserCommand::ValidateOtp {
                user_id: body.user_id.clone(),
                token: body.token.clone(),
            },
        );

        match self.command_handler.handle_command(command).await {
            Ok(CommandResult::OtpValidated { is_valid }) => Ok(is_valid),
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected command result"})),
            )),
            Err(err) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command failed: {}", err)})),
            )),
        }
    }

    /// Disable OTP (Command)
    pub async fn disable_otp(
        &self,
        body: &DisableOTPSchema,
    ) -> Result<UserData, impl IntoResponse> {
        let command = CommandEnvelope::new(
            body.user_id.clone(),
            UserCommand::DisableOtp {
                user_id: body.user_id.clone(),
            },
        );

        match self.command_handler.handle_command(command).await {
            Ok(CommandResult::OtpDisabled { user_data }) => Ok(user_data),
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected command result"})),
            )),
            Err(err) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Command failed: {}", err)})),
            )),
        }
    }

    /// Get user by ID (Query)
    pub async fn get_user_by_id(
        &self,
        user_id: &str,
    ) -> Result<Option<crate::models::User>, impl IntoResponse> {
        let query = UserQuery::GetUserById {
            user_id: user_id.to_string(),
        };

        match self.query_handler.handle_query(query).await {
            Ok(QueryResult::User(user)) => Ok(Some(user)),
            Ok(QueryResult::UserNotFound) => Ok(None),
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected query result"})),
            )),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Query failed"})),
            )),
        }
    }

    /// Get user by email (Query)
    pub async fn get_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<crate::models::User>, impl IntoResponse> {
        let query = UserQuery::GetUserByEmail {
            email: email.to_string(),
        };

        match self.query_handler.handle_query(query).await {
            Ok(QueryResult::User(user)) => Ok(Some(user)),
            Ok(QueryResult::UserNotFound) => Ok(None),
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected query result"})),
            )),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Query failed"})),
            )),
        }
    }

    /// Get all users (Query)
    pub async fn get_all_users(&self) -> Result<Vec<crate::models::User>, impl IntoResponse> {
        let query = UserQuery::GetAllUsers;

        match self.query_handler.handle_query(query).await {
            Ok(QueryResult::Users(users)) => Ok(users),
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected query result"})),
            )),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Query failed"})),
            )),
        }
    }

    /// Get users with OTP enabled (Query)
    pub async fn get_users_with_otp_enabled(
        &self,
    ) -> Result<Vec<crate::models::User>, impl IntoResponse> {
        let query = UserQuery::GetUsersWithOtpEnabled;

        match self.query_handler.handle_query(query).await {
            Ok(QueryResult::Users(users)) => Ok(users),
            Ok(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unexpected query result"})),
            )),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Query failed"})),
            )),
        }
    }

    /// Get user statistics (Query)
    pub async fn get_user_stats(&self) -> Result<crate::cqrs::UserStats, impl IntoResponse> {
        match self.query_handler.get_user_stats().await {
            Ok(stats) => Ok(stats),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to get user statistics"})),
            )),
        }
    }
}
