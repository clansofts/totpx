use crate::{
    models::{
        AppState, DisableOTPSchema, GenerateOTPSchema, UserLoginSchema, UserRegisterSchema,
        VerifyOTPSchema,
    },
    services::UserService,
};
use actix_web::{HttpResponse, Responder, get, post, web};
use serde_json::json;

#[get("/healthchecker")]
async fn health_checker_handler() -> impl Responder {
    const MESSAGE: &str = "How to Implement Two-Factor Authentication (2FA) in Rust";

    HttpResponse::Ok().json(json!({"status": "success", "message": MESSAGE}))
}

#[post("/auth/register")]
async fn register_user_handler(
    body: web::Json<UserRegisterSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    match UserService::register_user(&body, &data).await {
        Ok(message) => HttpResponse::Ok().json(json!({"status": "success", "message": message})),
        Err(error_response) => error_response,
    }
}

#[post("/auth/login")]
async fn login_user_handler(
    body: web::Json<UserLoginSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    match UserService::login_user(&body, &data).await {
        Ok(user_response) => HttpResponse::Ok().json(user_response),
        Err(error_response) => HttpResponse::InternalServerError().json(json!({
            "error": error_response.to_string()
        })),
    }
}

#[post("/auth/otp/generate")]
async fn generate_otp_handler(
    body: web::Json<GenerateOTPSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    match UserService::generate_otp(&body, &data).await {
        Ok((base32, otp_auth_url)) => HttpResponse::Ok().json(json!({
            "base32": base32,
            "otpauth_url": otp_auth_url
        })),
        Err(error_response) => error_response,
    }
}

#[post("/auth/otp/verify")]
async fn verify_otp_handler(
    body: web::Json<VerifyOTPSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    match UserService::verify_otp(&body, &data).await {
        Ok(user_data) => HttpResponse::Ok().json(json!({
            "otp_verified": true,
            "user": user_data
        })),
        Err(error_response) => error_response,
    }
}

#[post("/auth/otp/validate")]
async fn validate_otp_handler(
    body: web::Json<VerifyOTPSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    match UserService::validate_otp(&body, &data).await {
        Ok(_) => HttpResponse::Ok().json(json!({"otp_valid": true})),
        Err(error_response) => error_response,
    }
}

#[post("/auth/otp/disable")]
async fn disable_otp_handler(
    body: web::Json<DisableOTPSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    match UserService::disable_otp(&body, &data).await {
        Ok(user_data) => HttpResponse::Ok().json(json!({
            "user": user_data,
            "otp_disabled": true
        })),
        Err(error_response) => error_response,
    }
}

pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api")
        .service(health_checker_handler)
        .service(register_user_handler)
        .service(login_user_handler)
        .service(generate_otp_handler)
        .service(verify_otp_handler)
        .service(validate_otp_handler)
        .service(disable_otp_handler);

    conf.service(scope);
}
