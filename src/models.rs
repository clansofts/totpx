use std::sync::Arc;

use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use surrealdb::engine::local::{Db, Mem};
use surrealdb::engine::remote::ws::{Client, Ws};
use surrealdb::opt::auth::Root;
use surrealdb::{Datetime, RecordId, Result as SurrealResult, Surreal};

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

pub struct AppState {
    pub db: Arc<Surreal<Client>>,
}

impl AppState {
    pub async fn init() -> SurrealResult<AppState> {
        println!("Initializing Authentication Database Connection");
        let address = String::from("0.0.0.0:5555");
        let username = String::from("root");
        let secret = String::from("@Cr34f1n1ty");
        let namespace = String::from("malipo");
        let database = String::from("eventors");

        // Initialize SurrealDB
        let db = Surreal::new::<Ws>(address).await?;

        // Signin as a namespace, database, or root user
        db.signin(Root {
            username: &username,
            password: &secret,
        })
        .await?;

        // Select a specific namespace / database
        db.use_ns(namespace).use_db(database).await?;

        Ok(AppState { db: Arc::new(db) })
    }
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
