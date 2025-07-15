use crate::{
    cqrs_service::CqrsUserService,
    db::AppState,
    models::{
        DisableOTPSchema, GenerateOTPSchema, UserLoginSchema, UserRegisterSchema, VerifyOTPSchema,
    },
    response::GenOtpResponse,
};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use serde_json::{Value, json};

async fn health_checker_handler() -> Json<Value> {
    const MESSAGE: &str = "CQRS-based Two-Factor Authentication (2FA) in Rust with Event Sourcing";

    Json(json!({"status": "success", "message": MESSAGE}))
}

async fn register_user_handler(
    State(data): State<AppState>,
    Json(body): Json<UserRegisterSchema>,
) -> Response {
    let service = CqrsUserService::new(data);

    match service.register_user(&body).await {
        Ok(message) => {
            let response = json!({"status": "success", "message": message});
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error_response) => error_response.into_response(),
    }
}

async fn login_user_handler(
    State(data): State<AppState>,
    Json(body): Json<UserLoginSchema>,
) -> Response {
    let service = CqrsUserService::new(data);

    match service.login_user(&body).await {
        Ok(user_response) => (StatusCode::OK, Json(user_response)).into_response(),
        Err(error) => {
            let response = json!({"status": "error", "message": error.to_string()});
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

async fn generate_otp_handler(
    State(data): State<AppState>,
    Json(body): Json<GenerateOTPSchema>,
) -> Response {
    let service = CqrsUserService::new(data);

    match service.generate_otp(&body).await {
        Ok((base32_secret, otp_auth_url)) => {
            let response = GenOtpResponse {
                base32_secret,
                otp_auth_url,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error_response) => error_response.into_response(),
    }
}

async fn verify_otp_handler(
    State(data): State<AppState>,
    Json(body): Json<VerifyOTPSchema>,
) -> Response {
    let service = CqrsUserService::new(data);

    match service.verify_otp(&body).await {
        Ok(user_data) => (StatusCode::OK, Json(user_data)).into_response(),
        Err(error_response) => error_response.into_response(),
    }
}

async fn validate_otp_handler(
    State(data): State<AppState>,
    Json(body): Json<VerifyOTPSchema>,
) -> Response {
    let service = CqrsUserService::new(data);

    match service.validate_otp(&body).await {
        Ok(is_valid) => {
            let response = json!({"status": "success", "valid": is_valid});
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error_response) => error_response.into_response(),
    }
}

async fn disable_otp_handler(State(data): State<AppState>, body: DisableOTPSchema) -> Response {
    let service = CqrsUserService::new(data);

    match service.disable_otp(&body).await {
        Ok(user_data) => (StatusCode::OK, Json(user_data)).into_response(),
        Err(error_response) => error_response.into_response(),
    }
}

// Query endpoints
async fn get_user_by_id_handler(
    State(data): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Response {
    let service = CqrsUserService::new(data);

    match service.get_user_by_id(&user_id).await {
        Ok(user_data) => (StatusCode::OK, Json(user_data)).into_response(),
        Err((error_json)) => (error_json).into_response(),
    }
}

async fn get_user_by_email_handler(
    State(data): State<AppState>,
    axum::extract::Path(email): axum::extract::Path<String>,
) -> Response {
    let service = CqrsUserService::new(data);

    match service.get_user_by_email(&email).await {
        Ok(user_data) => (StatusCode::OK, Json(user_data)).into_response(),
        Err(error_json) => (error_json).into_response(),
    }
}

async fn get_all_users_handler(State(data): State<AppState>) -> Response {
    let service = CqrsUserService::new(data);

    match service.get_all_users().await {
        Ok(users) => {
            let response = json!({"status": "success", "users": users});
            (StatusCode::OK, Json(response)).into_response()
        }
        Err((error_json)) => (error_json).into_response(),
    }
}

async fn get_users_with_otp_enabled_handler(State(data): State<AppState>) -> Response {
    let service = CqrsUserService::new(data);

    match service.get_users_with_otp_enabled().await {
        Ok(users) => {
            let response = json!({"status": "success", "users": users});
            (StatusCode::OK, Json(response)).into_response()
        }
        Err((error_json)) => (error_json).into_response(),
    }
}

async fn get_user_stats_handler(State(data): State<AppState>) -> Response {
    let service = CqrsUserService::new(data);

    match service.get_user_stats().await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err((error_json)) => (error_json).into_response(),
    }
}
pub fn create_cqrs_router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_checker_handler))
        .route("/register", post(register_user_handler))
        .route("/login", post(login_user_handler))
        .route("/generate_otp", post(generate_otp_handler))
        .route("/verify_otp", post(verify_otp_handler))
        .route("/validate_otp", post(validate_otp_handler))
        .route("/disable_otp", post(disable_otp_handler))
        .route("/user/:user_id", get(get_user_by_id_handler))
        .route("/user/email/:email", get(get_user_by_email_handler))
        .route("/users", get(get_all_users_handler))
        .route(
            "/users/otp_enabled",
            get(get_users_with_otp_enabled_handler),
        )
        .route("/user_stats", get(get_user_stats_handler))
}
