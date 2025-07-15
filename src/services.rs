use crate::{
    cqrs_service::CqrsUserService,
    db::AppState,
    models::{
        DisableOTPSchema, GenerateOTPSchema, SigninParams, SignupParams, User, UserLoginSchema,
        UserRegisterSchema, VerifyOTPSchema,
    },
    response::{GenOtpResponse, GenericResponse, UserData, UserResponse},
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
};
use chrono::prelude::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use surrealdb::{Datetime, Error, opt::auth::Record};
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    DatabaseError(String),
    #[error("{0}")]
    UserExists(String),
    #[error("{0}")]
    UserNotFound(String),
    #[error("{0}")]
    OtpError(String),
    #[error("{0}")]
    TokenInvalid(String),
    #[error("{0}")]
    InternalError(String),
    #[error("database error")]
    Db(String),
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ServiceError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ServiceError::UserExists(msg) => (StatusCode::CONFLICT, msg),
            ServiceError::UserNotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ServiceError::OtpError(msg) => (StatusCode::BAD_REQUEST, msg),
            ServiceError::TokenInvalid(msg) => (StatusCode::FORBIDDEN, msg),
            ServiceError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ServiceError::Db(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let error_response = GenericResponse {
            status: "fail".to_string(),
            message,
        };

        (status, Json(error_response)).into_response()
    }
}

// From<serde_json::Error> for ServiceError
impl From<serde_json::Error> for ServiceError {
    fn from(err: serde_json::Error) -> Self {
        ServiceError::InternalError(format!("JSON error: {}", err))
    }
}

// From<surrealdb::Error> for ServiceError
impl From<surrealdb::Error> for ServiceError {
    fn from(err: surrealdb::Error) -> Self {
        ServiceError::Db(format!("SurrealDB error: {}", err))
    }
}

impl Serialize for ServiceError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let message = self.to_string();
        serializer.serialize_str(&message)
    }
}

impl<'de> Deserialize<'de> for ServiceError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let message = String::deserialize(deserializer)?;
        Ok(ServiceError::InternalError(message))
    }
}

pub struct UserService;

impl UserService {
    pub async fn register_user(
        body: UserRegisterSchema,
        data: AppState,
    ) -> Result<String, ServiceError> {
        let service = CqrsUserService::new(data);
        
        match service.register_user(&body).await {
            Ok(message) => Ok(message),
            Err(_) => {
                // For now, fall back to a generic error
                Err(ServiceError::InternalError("Registration failed".to_string()))
            }
        }
    }

    pub async fn login_user(body: UserLoginSchema, data: AppState) -> Result<UserResponse, Error> {
        let service = CqrsUserService::new(data);
        
        match service.login_user(&body).await {
            Ok(response) => Ok(response),
            Err(error) => Err(error),
        }
    }

    pub async fn generate_otp(
        body: GenerateOTPSchema,
        data: AppState,
    ) -> Result<GenOtpResponse, ServiceError> {
        let service = CqrsUserService::new(data);
        
        match service.generate_otp(&body).await {
            Ok((base32_secret, otp_auth_url)) => {
                Ok(GenOtpResponse {
                    base32_secret,
                    otp_auth_url,
                })
            }
            Err(_) => {
                Err(ServiceError::OtpError("Failed to generate OTP".to_string()))
            }
        }
    }

    pub async fn verify_otp(
        body: VerifyOTPSchema,
        data: AppState,
    ) -> Result<UserData, ServiceError> {
        let service = CqrsUserService::new(data);
        
        match service.verify_otp(&body).await {
            Ok(user_data) => Ok(user_data),
            Err(_) => {
                Err(ServiceError::TokenInvalid("Token verification failed".to_string()))
            }
        }
    }

    pub async fn validate_otp(body: VerifyOTPSchema, data: AppState) -> Result<bool, ServiceError> {
        let service = CqrsUserService::new(data);
        
        match service.validate_otp(&body).await {
            Ok(is_valid) => Ok(is_valid),
            Err(_) => {
                Err(ServiceError::TokenInvalid("Token validation failed".to_string()))
            }
        }
    }

    pub async fn disable_otp(
        body: DisableOTPSchema,
        data: AppState,
    ) -> Result<UserData, ServiceError> {
        let service = CqrsUserService::new(data);
        
        match service.disable_otp(&body).await {
            Ok(user_data) => Ok(user_data),
            Err(_) => {
                Err(ServiceError::InternalError("Failed to disable OTP".to_string()))
            }
        }
    }

    fn user_to_response(user: &User) -> UserData {
        UserData {
            id: user.id.as_ref().map_or("".to_string(), |id| id.to_string()),
            username: user.username.to_owned(),
            secret: user.secret.to_owned(),
            otp_auth_url: user.otp_auth_url.to_owned(),
            otp_secret: user.otp_secret.to_owned(),
            otp_enabled: user.otp_enabled.unwrap(),
            otp_verified: user.otp_verified.unwrap(),
            stamp: user.stamp.clone().unwrap().to_string(),
            changed: user.changed.clone().unwrap().to_string(),
            category: user.category.to_owned(),
            stakeholder: user.stakeholder.to_owned(),
            status: user.status.to_owned(),
            expired: user.expired.unwrap_or(false),
            verified: user.verified.unwrap_or(false),
        }
    }
}
