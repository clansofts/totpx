use crate::{
    models::{
        AppState, DisableOTPSchema, GenerateOTPSchema, SigninParams, SignupParams, User,
        UserLoginSchema, UserRegisterSchema, VerifyOTPSchema,
    },
    response::{GenericResponse, UserData, UserResponse},
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
};
use chrono::prelude::*;
use std::sync::Arc;
use surrealdb::{Datetime, Error, opt::auth::Record};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

#[derive(Debug)]
pub enum ServiceError {
    DatabaseError(String),
    UserExists(String),
    UserNotFound(String),
    OtpError(String),
    TokenInvalid(String),
    InternalError(String),
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
        };

        let error_response = GenericResponse {
            status: "fail".to_string(),
            message,
        };

        (status, Json(error_response)).into_response()
    }
}

pub struct UserService;

impl UserService {
    pub async fn register_user(
        body: &UserRegisterSchema,
        data: &Arc<AppState>,
    ) -> Result<String, ServiceError> {
        // Get the db
        let db = data.db.clone();
        // Check if user already exists
        let existing_users: Vec<User> = match db.select("mcp_auth").await {
            Ok(users) => users,
            Err(_) => {
                return Err(ServiceError::DatabaseError(
                    "Database error occurred".to_string(),
                ));
            }
        };

        for user in existing_users.iter() {
            if user.username == body.email.to_lowercase() {
                return Err(ServiceError::UserExists(format!(
                    "User with email: {} already exists",
                    user.username
                )));
            }
        }

        let _uuid_id = Uuid::new_v4();
        let datetime = Utc::now();

        let user = User {
            id: None,
            username: body.email.to_owned().to_lowercase(),
            status: body.name.to_owned(),
            secret: body.password.to_owned(),
            otp_enabled: Some(false),
            otp_verified: Some(false),
            otp_secret: None,
            otp_auth_url: None,
            stamp: Some(Datetime::from(datetime)),
            changed: Some(Datetime::from(datetime)),
            category: "Root".to_string(),
            stakeholder: "".to_string(),
            expired: Some(false),
            verified: Some(false),
        };

        // Signup the user on surrealdb
        let jwt = match db
            .signup(Record {
                access: "mcp_authx",
                namespace: "malipo",
                database: "eventors",
                params: SignupParams {
                    username: user.username.as_str(),
                    secret: user.secret.as_str(),
                    category: "App/Individual/Organization",
                    stakeholder: "",
                    status: "New",
                },
            })
            .await
        {
            Ok(token) => token.into_insecure_token(),
            Err(_) => {
                return Err(ServiceError::InternalError(
                    "Failed to signup user".to_string(),
                ));
            }
        };

        Ok(format!(
            "Registered successfully, please login with token: {}",
            jwt
        ))
    }

    pub async fn login_user(
        body: &UserLoginSchema,
        data: &Arc<AppState>,
    ) -> Result<UserResponse, Error> {
        let db = data.db.clone();

        // Signin using user credentials
        match db
            .signin(Record {
                access: "mcp_authx",
                namespace: "malipo",
                database: "eventors",
                params: SigninParams {
                    username: body.email.as_str(),
                    secret: body.password.as_str(),
                },
            })
            .await
        {
            Ok(token) => {
                let token = token.into_insecure_token();
                println!("Token: {}", token.clone());
                // Run queries
                let mut result = db
                    .query("select * from only  mcp_auth where username = $username")
                    .bind(("username", body.email.clone().to_lowercase()))
                    .await?;

                let ress: Option<User> = result.take(0)?;
                println!("Result: {:?}", ress.clone());
                let user = ress.unwrap();

                let json_response = UserResponse {
                    status: "success".to_string(),
                    user: Self::user_to_response(&user),
                };
                Ok(json_response)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn generate_otp(
        body: &GenerateOTPSchema,
        _data: &Arc<AppState>,
    ) -> Result<(String, String), ServiceError> {
        Ok((body.email.clone(), body.user_id.clone()))
    }

    pub async fn verify_otp(
        body: &VerifyOTPSchema,
        data: &Arc<AppState>,
    ) -> Result<UserData, ServiceError> {
        let db = data.db.clone();
        // Find the user by ID
        let user: Option<User> = match data.db.select(("mcp_auth", &body.user_id)).await {
            Ok(user) => user,
            Err(_) => {
                return Err(ServiceError::DatabaseError(
                    "Database error occurred".to_string(),
                ));
            }
        };

        let mut user = match user {
            Some(u) => u,
            None => {
                return Err(ServiceError::UserNotFound(format!(
                    "No user with Id: {} found",
                    body.user_id
                )));
            }
        };

        let otp_base32 = match &user.otp_secret {
            Some(secret) => secret.clone(),
            None => {
                return Err(ServiceError::OtpError(
                    "OTP not generated for this user".to_string(),
                ));
            }
        };

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(otp_base32).to_bytes().unwrap(),
        )
        .unwrap();

        let is_valid = totp.check_current(&body.token).unwrap();

        if !is_valid {
            return Err(ServiceError::TokenInvalid(
                "Token is invalid or user doesn't exist".to_string(),
            ));
        }

        user.otp_enabled = Some(true);
        user.otp_verified = Some(true);

        // Update the user in the database
        let updated_user: Option<User> = match db
            .update(("mcp_auth", &body.user_id))
            .content(user.clone())
            .await
        {
            Ok(updated) => updated,
            Err(_) => {
                return Err(ServiceError::InternalError(
                    "Failed to update user verification status".to_string(),
                ));
            }
        };

        match updated_user {
            Some(u) => Ok(Self::user_to_response(&u)),
            None => Ok(Self::user_to_response(&user)),
        }
    }

    pub async fn validate_otp(
        body: &VerifyOTPSchema,
        data: &Arc<AppState>,
    ) -> Result<bool, ServiceError> {
        // Find the user by ID
        let user: Option<User> = match data.db.select(("mcp_auth", &body.user_id)).await {
            Ok(user) => user,
            Err(_) => {
                return Err(ServiceError::DatabaseError(
                    "Database error occurred".to_string(),
                ));
            }
        };

        let user = match user {
            Some(u) => u,
            None => {
                return Err(ServiceError::UserNotFound(format!(
                    "No user with Id: {} found",
                    body.user_id
                )));
            }
        };

        if !user.otp_enabled.unwrap_or(false) {
            return Err(ServiceError::TokenInvalid("2FA not enabled".to_string()));
        }

        let otp_base32 = match &user.otp_secret {
            Some(secret) => secret.clone(),
            None => {
                return Err(ServiceError::OtpError("OTP secret not found".to_string()));
            }
        };

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(otp_base32).to_bytes().unwrap(),
        )
        .unwrap();

        let is_valid = totp.check_current(&body.token).unwrap();

        if !is_valid {
            return Err(ServiceError::TokenInvalid(
                "Token is invalid or user doesn't exist".to_string(),
            ));
        }

        Ok(true)
    }

    pub async fn disable_otp(
        body: &DisableOTPSchema,
        data: &Arc<AppState>,
    ) -> Result<UserData, ServiceError> {
        let db = data.db.clone();
        // Find the user by ID
        let user: Option<User> = match data.db.select(("mcp_auth", &body.user_id)).await {
            Ok(user) => user,
            Err(_) => {
                return Err(ServiceError::DatabaseError(
                    "Database error occurred".to_string(),
                ));
            }
        };

        let mut user = match user {
            Some(u) => u,
            None => {
                return Err(ServiceError::UserNotFound(format!(
                    "No user with Id: {} found",
                    body.user_id
                )));
            }
        };

        user.otp_enabled = Some(false);
        user.otp_verified = Some(false);
        user.otp_auth_url = None;
        user.otp_secret = None;

        // Update the user in the database
        let updated_user: Option<User> = match db
            .update(("mcp_auth", &body.user_id))
            .content(user.clone())
            .await
        {
            Ok(updated) => updated,
            Err(_) => {
                return Err(ServiceError::InternalError(
                    "Failed to disable OTP for user".to_string(),
                ));
            }
        };

        match updated_user {
            Some(u) => Ok(Self::user_to_response(&u)),
            None => Ok(Self::user_to_response(&user)),
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
