use serde::Serialize;

#[derive(Serialize)]
pub struct GenericResponse {
    pub status: String,
    pub message: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Debug)]
pub struct UserData {
    pub id: String,
    pub username: String,
    pub secret: String,
    pub category: String,
    pub stakeholder: String,
    pub status: String,
    pub expired: bool,
    pub verified: bool,
    pub otp_secret: Option<String>,
    pub otp_auth_url: Option<String>,
    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub stamp: String,
    pub changed: String,
}

#[derive(Serialize, Debug)]
pub struct UserResponse {
    pub status: String,
    pub user: UserData,
}

#[allow(non_snake_case)]
#[derive(Serialize, Debug)]
pub struct GenOtpResponse {
    pub base32_secret: String,
    pub otp_auth_url: String,
}
