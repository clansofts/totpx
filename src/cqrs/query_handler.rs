use crate::cqrs::{QueryResult, UserQuery};
use crate::db::AppState;
use crate::models::User;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Query error: {0}")]
    QueryError(String),
}

impl From<surrealdb::Error> for QueryError {
    fn from(err: surrealdb::Error) -> Self {
        QueryError::DatabaseError(err.to_string())
    }
}

/// Query Handler responsible for reading from the read model (mcp_auth table)
pub struct QueryHandler {
    pub db: AppState,
}

impl QueryHandler {
    pub fn new(db: AppState) -> Self {
        Self { db }
    }

    /// Execute a query and return the result
    pub async fn handle_query(&self, query: UserQuery) -> Result<QueryResult, QueryError> {
        match query {
            UserQuery::GetUserById { user_id } => self.get_user_by_id(&user_id).await,
            UserQuery::GetUserByEmail { email } => self.get_user_by_email(&email).await,
            UserQuery::GetUserByUsername { username } => self.get_user_by_username(&username).await,
            UserQuery::GetAllUsers => self.get_all_users().await,
            UserQuery::GetUsersWithOtpEnabled => self.get_users_with_otp_enabled().await,
        }
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<QueryResult, QueryError> {
        let user: Option<User> = self.db.db.select(("mcp_auth", user_id)).await?;

        match user {
            Some(u) => Ok(QueryResult::User(u)),
            None => Ok(QueryResult::UserNotFound),
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<QueryResult, QueryError> {
        let mut result = self
            .db
            .db
            .query("SELECT * FROM mcp_auth WHERE username = $email LIMIT 1")
            .bind(("email", email.to_lowercase()))
            .await?;

        let user: Option<User> = result.take(0)?;

        match user {
            Some(u) => Ok(QueryResult::User(u)),
            None => Ok(QueryResult::UserNotFound),
        }
    }

    async fn get_user_by_username(&self, username: &str) -> Result<QueryResult, QueryError> {
        let mut result = self
            .db
            .db
            .query("SELECT * FROM mcp_auth WHERE username = $username LIMIT 1")
            .bind(("username", username.to_lowercase()))
            .await?;

        let user: Option<User> = result.take(0)?;

        match user {
            Some(u) => Ok(QueryResult::User(u)),
            None => Ok(QueryResult::UserNotFound),
        }
    }

    async fn get_all_users(&self) -> Result<QueryResult, QueryError> {
        println!("get_all_users called");

        let mut result = self
            .db
            .db
            .query("SELECT * FROM mcp_auth WHERE verified = true")
            .await?;

        let users: Vec<User> = result.take(0)?;

        println!("Users Allowed In System {:?}", users.clone());

        Ok(QueryResult::Users(users))
    }

    async fn get_users_with_otp_enabled(&self) -> Result<QueryResult, QueryError> {
        let mut result = self
            .db
            .db
            .query("SELECT * FROM mcp_auth WHERE otp_enabled = true")
            .await?;

        let users: Vec<User> = result.take(0)?;

        Ok(QueryResult::Users(users))
    }

    /// Get user statistics
    pub async fn get_user_stats(&self) -> Result<UserStats, QueryError> {
        let mut total_result = self
            .db
            .db
            .query("SELECT count() as total FROM mcp_auth")
            .await?;

        let mut otp_enabled_result = self
            .db
            .db
            .query("SELECT count() as otp_enabled FROM mcp_auth WHERE otp_enabled = true")
            .await?;

        let mut otp_verified_result = self
            .db
            .db
            .query("SELECT count() as otp_verified FROM mcp_auth WHERE otp_verified = true")
            .await?;

        let total: Option<CountResult> = total_result.take(0)?;
        let otp_enabled: Option<CountResult> = otp_enabled_result.take(0)?;
        let otp_verified: Option<CountResult> = otp_verified_result.take(0)?;

        Ok(UserStats {
            total_users: total.map(|t| t.total).unwrap_or(0),
            users_with_otp_enabled: otp_enabled.map(|o| o.total).unwrap_or(0),
            users_with_otp_verified: otp_verified.map(|o| o.total).unwrap_or(0),
        })
    }
}

#[derive(Debug, serde::Deserialize)]
struct CountResult {
    total: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct UserStats {
    pub total_users: i64,
    pub users_with_otp_enabled: i64,
    pub users_with_otp_verified: i64,
}
