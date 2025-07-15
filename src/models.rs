use serde::{Deserialize, Serialize};
use surrealdb::{Datetime, RecordId};

#[derive(Serialize, Deserialize)]
pub struct SignupParams<'a> {
    pub username: &'a str,
    pub secret: &'a str,
    pub category: &'a str,
    pub stakeholder: &'a str,
    pub status: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct SigninParams<'a> {
    pub username: &'a str,
    pub secret: &'a str,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub id: Option<RecordId>,
    pub category: String,
    pub username: String,
    pub status: String,
    pub secret: String,
    pub stakeholder: String,
    pub expired: Option<bool>,
    pub verified: Option<bool>,
    pub otp_enabled: Option<bool>,
    pub otp_verified: Option<bool>,
    pub otp_secret: Option<String>,
    pub otp_auth_url: Option<String>,

    pub stamp: Option<Datetime>,
    pub changed: Option<Datetime>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User2Fa {
    pub otp_secret: Option<String>,
    pub otp_auth_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserRegisterSchema {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UserLoginSchema {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerateOTPSchema {
    pub email: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyOTPSchema {
    pub user_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct DisableOTPSchema {
    pub user_id: String,
}
