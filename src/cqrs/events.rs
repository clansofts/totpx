use serde::{Deserialize, Serialize};
use surrealdb::Datetime;
use uuid::Uuid;

/// Domain Events that represent state changes in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum UserEvent {
    UserRegistered {
        user_id: String,
        username: String,
        secret: String,
        category: String,
        stakeholder: String,
        status: String,
    },
    UserLoggedIn {
        user_id: String,
        username: String,
        timestamp: Datetime,
    },
    OtpSecretGenerated {
        user_id: String,
        email: String,
        otp_secret: String,
        otp_auth_url: String,
    },
    OtpVerified {
        user_id: String,
        otp_enabled: bool,
        otp_verified: bool,
    },
    OtpValidated {
        user_id: String,
        token: String,
        is_valid: bool,
    },
    OtpDisabled {
        user_id: String,
    },
}

/// Event envelope that wraps domain events with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub aggregate_id: String,
    pub aggregate_type: String,
    pub event_version: u64,
    pub event_data: UserEvent,
    pub timestamp: Datetime,
}

impl EventEnvelope {
    pub fn new(aggregate_id: String, event_data: UserEvent) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id,
            aggregate_type: "User".to_string(),
            event_version: 1,
            event_data,
            timestamp: Datetime::default(),
        }
    }
}
