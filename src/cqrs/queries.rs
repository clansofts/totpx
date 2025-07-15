use serde::{Deserialize, Serialize};

/// Query models for reading data from the read model (mcp_auth table)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "query_type")]
pub enum UserQuery {
    GetUserById { user_id: String },
    GetUserByEmail { email: String },
    GetUserByUsername { username: String },
    GetAllUsers,
    GetUsersWithOtpEnabled,
}

/// Query results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryResult {
    User(crate::models::User),
    Users(Vec<crate::models::User>),
    UserNotFound,
    Error(String),
}
