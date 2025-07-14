use crate::{
    models::{
        AppState, DisableOTPSchema, GenerateOTPSchema, UserLoginSchema, UserRegisterSchema,
        VerifyOTPSchema,
    },
    services::UserService,
};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::Arc;

async fn health_checker_handler() -> Json<Value> {
    const MESSAGE: &str = "How to Implement Two-Factor Authentication (2FA) in Rust";

    Json(json!({"status": "success", "message": MESSAGE}))
}

async fn register_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<UserRegisterSchema>,
) -> Response {
    match UserService::register_user(&body, &data).await {
        Ok(message) => {
            let response = json!({"status": "success", "message": message});
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<UserLoginSchema>,
) -> Response {
    match UserService::login_user(&body, &data).await {
        Ok(user_response) => (StatusCode::OK, Json(user_response)).into_response(),
        Err(error_response) => {
            let response = json!({
                "error": error_response.to_string()
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

async fn generate_otp_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<GenerateOTPSchema>,
) -> impl IntoResponse {
    match UserService::generate_otp(&body, &data).await {
        Ok((base32, otp_auth_url)) => {
            let response = json!({
                "base32": base32,
                "otpauth_url": otp_auth_url
            });
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn verify_otp_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<VerifyOTPSchema>,
) -> Response {
    match UserService::verify_otp(&body, &data).await {
        Ok(user_data) => {
            let response = json!({
                "otp_verified": true,
                "user": user_data
            });
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn validate_otp_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<VerifyOTPSchema>,
) -> Response {
    match UserService::validate_otp(&body, &data).await {
        Ok(_) => {
            let response = json!({"otp_valid": true});
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn disable_otp_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<DisableOTPSchema>,
) -> Response {
    match UserService::disable_otp(&body, &data).await {
        Ok(user_data) => {
            let response = json!({
                "user": user_data,
                "otp_disabled": true
            });
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => error.into_response(),
    }
}

pub fn create_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/healthchecker", get(health_checker_handler))
        .route("/api/auth/register", post(register_user_handler))
        .route("/api/auth/login", post(login_user_handler))
        .route("/api/auth/otp/generate", post(generate_otp_handler))
        .route("/api/auth/otp/verify", post(verify_otp_handler))
        .route("/api/auth/otp/validate", post(validate_otp_handler))
        .route("/api/auth/otp/disable", post(disable_otp_handler))
}
