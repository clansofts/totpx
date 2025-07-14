use crate::{
    models::{
        AppState, DisableOTPSchema, GenerateOTPSchema, SigninParams, SignupParams, User,
        UserLoginSchema, UserRegisterSchema, VerifyOTPSchema,
    },
    response::{GenericResponse, UserData, UserResponse},
};
use actix_web::{HttpResponse, web};
use base32;
use chrono::prelude::*;
use rand::Rng;
use serde_json::json;
use surrealdb::{Datetime, Error, opt::auth::Record};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

pub struct UserService;

impl UserService {
    pub async fn register_user(
        body: &UserRegisterSchema,
        data: &web::Data<AppState>,
    ) -> Result<String, HttpResponse> {
        // Get the db
        let db = data.db.clone();
        // Check if user already exists
        let existing_users: Vec<User> = match db.select("mcp_auth").await {
            Ok(users) => users,
            Err(_) => {
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: "Database error occurred".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(error_response));
            }
        };

        for user in existing_users.iter() {
            if user.username == body.email.to_lowercase() {
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("User with email: {} already exists", user.username),
                };
                return Err(HttpResponse::Conflict().json(error_response));
            }
        }

        let uuid_id = Uuid::new_v4();
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
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: "Failed to signup user".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(error_response));
            }
        };

        Ok(format!(
            "Registered successfully, please login with token: {}",
            jwt
        ))
    }

    pub async fn login_user(
        body: &UserLoginSchema,
        data: &web::Data<AppState>,
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
        data: &web::Data<AppState>,
    ) -> Result<(String, String), HttpResponse> {
        // Find the user by ID
        let user: Option<User> = match data.db.select(("mcp_auth", &body.user_id)).await {
            Ok(user) => user,
            Err(_) => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "Database error occurred".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(json_error));
            }
        };

        let mut user = match user {
            Some(u) => u,
            None => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("No user with Id: {} found", body.user_id),
                };
                return Err(HttpResponse::NotFound().json(json_error));
            }
        };

        let mut rng = rand::rng();
        let data_byte: [u8; 21] = rng.random();
        let base32_string =
            base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &data_byte);

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(base32_string).to_bytes().unwrap(),
        )
        .unwrap();

        let otp_base32 = totp.get_secret_base32();
        let email = body.email.to_owned();
        let issuer = "Malipo Popote Solutions";
        let otp_auth_url =
            format!("otpauth://totp/{issuer}:{email}?secret={otp_base32}&issuer={issuer}");

        // Update user with OTP data
        user.otp_secret = Some(otp_base32.to_owned());
        user.otp_auth_url = Some(otp_auth_url.to_owned());

        // Update the user in the database
        let _updated: Option<User> = match data
            .db
            .update(("mcp_auth", &body.user_id))
            .content(user)
            .await
        {
            Ok(updated) => updated,
            Err(_) => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "Failed to update user with OTP data".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(json_error));
            }
        };

        Ok((otp_base32, otp_auth_url))
    }

    pub async fn verify_otp(
        body: &VerifyOTPSchema,
        data: &web::Data<AppState>,
    ) -> Result<UserData, HttpResponse> {
        let db = data.db.clone();
        // Find the user by ID
        let user: Option<User> = match data.db.select(("mcp_auth", &body.user_id)).await {
            Ok(user) => user,
            Err(_) => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "Database error occurred".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(json_error));
            }
        };

        let mut user = match user {
            Some(u) => u,
            None => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("No user with Id: {} found", body.user_id),
                };
                return Err(HttpResponse::NotFound().json(json_error));
            }
        };

        let otp_base32 = match &user.otp_secret {
            Some(secret) => secret.clone(),
            None => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "OTP not generated for this user".to_string(),
                };
                return Err(HttpResponse::BadRequest().json(json_error));
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
            let json_error = GenericResponse {
                status: "fail".to_string(),
                message: "Token is invalid or user doesn't exist".to_string(),
            };
            return Err(HttpResponse::Forbidden().json(json_error));
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
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "Failed to update user verification status".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(json_error));
            }
        };

        match updated_user {
            Some(u) => Ok(Self::user_to_response(&u)),
            None => Ok(Self::user_to_response(&user)),
        }
    }

    pub async fn validate_otp(
        body: &VerifyOTPSchema,
        data: &web::Data<AppState>,
    ) -> Result<bool, HttpResponse> {
        // Find the user by ID
        let user: Option<User> = match data.db.select(("mcp_auth", &body.user_id)).await {
            Ok(user) => user,
            Err(_) => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "Database error occurred".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(json_error));
            }
        };

        let user = match user {
            Some(u) => u,
            None => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("No user with Id: {} found", body.user_id),
                };
                return Err(HttpResponse::NotFound().json(json_error));
            }
        };

        if !user.otp_enabled.unwrap_or(false) {
            let json_error = GenericResponse {
                status: "fail".to_string(),
                message: "2FA not enabled".to_string(),
            };
            return Err(HttpResponse::Forbidden().json(json_error));
        }

        let otp_base32 = match &user.otp_secret {
            Some(secret) => secret.clone(),
            None => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "OTP secret not found".to_string(),
                };
                return Err(HttpResponse::BadRequest().json(json_error));
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
            let error_response =
                json!({"status": "fail", "message": "Token is invalid or user doesn't exist"});
            return Err(HttpResponse::Forbidden().json(error_response));
        }

        Ok(true)
    }

    pub async fn disable_otp(
        body: &DisableOTPSchema,
        data: &web::Data<AppState>,
    ) -> Result<UserData, HttpResponse> {
        let db = data.db.clone();
        // Find the user by ID
        let user: Option<User> = match data.db.select(("mcp_auth", &body.user_id)).await {
            Ok(user) => user,
            Err(_) => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "Database error occurred".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(json_error));
            }
        };

        let mut user = match user {
            Some(u) => u,
            None => {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("No user with Id: {} found", body.user_id),
                };
                return Err(HttpResponse::NotFound().json(json_error));
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
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: "Failed to disable OTP for user".to_string(),
                };
                return Err(HttpResponse::InternalServerError().json(json_error));
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
