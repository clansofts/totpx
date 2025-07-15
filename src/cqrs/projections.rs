use crate::cqrs::event_store::EventStoreError;
use crate::cqrs::{EventEnvelope, UserEvent};
use crate::db::AppState;
use crate::models::User;
use chrono::prelude::*;
use surrealdb::{Datetime, RecordId};
use uuid::Uuid;

/// Projection handler that updates read models based on events
pub struct UserProjection {
    pub db: AppState,
}

impl UserProjection {
    pub fn new(db: AppState) -> Self {
        Self { db }
    }

    /// Handle an event and update the read model accordingly
    pub async fn handle_event(&self, event: &EventEnvelope) -> Result<(), EventStoreError> {
        match &event.event_data {
            UserEvent::UserRegistered {
                user_id,
                username,
                secret,
                category,
                stakeholder,
                status,
            } => {
                self.create_user_read_model(
                    user_id,
                    username,
                    secret,
                    category,
                    stakeholder,
                    status,
                )
                .await?;
            }
            UserEvent::OtpSecretGenerated {
                user_id,
                email,
                otp_secret,
                otp_auth_url,
            } => {
                self.update_user_otp_secret(user_id, email, otp_secret, otp_auth_url)
                    .await?;
            }
            UserEvent::OtpVerified {
                user_id,
                otp_enabled,
                otp_verified,
            } => {
                self.update_user_otp_status(user_id, *otp_enabled, *otp_verified)
                    .await?;
            }
            UserEvent::OtpDisabled { user_id } => {
                self.disable_user_otp(user_id).await?;
            }
            UserEvent::UserLoggedIn {
                user_id, timestamp, ..
            } => {
                self.update_user_last_login(user_id, timestamp).await?;
            }
            UserEvent::OtpValidated { .. } => {
                // OtpValidated events don't typically update the read model
                // unless you want to track validation history
            }
        }
        Ok(())
    }

    /// Create a new user in the read model (mcp_auth table)
    async fn create_user_read_model(
        &self,
        user_id: &str,
        username: &str,
        secret: &str,
        category: &str,
        stakeholder: &str,
        status: &str,
    ) -> Result<(), EventStoreError> {
        let datetime = Utc::now();

        let user = User {
            id: Some(RecordId::from_table_key("mcp_auth", username)),
            username: username.to_lowercase(),
            status: status.to_owned(),
            secret: secret.to_owned(),
            otp_enabled: Some(false),
            otp_verified: Some(false),
            otp_secret: None,
            otp_auth_url: None,
            stamp: Some(Datetime::from(datetime)),
            changed: Some(Datetime::from(datetime)),
            category: category.to_string(),
            stakeholder: stakeholder.to_string(),
            expired: Some(false),
            verified: Some(false),
        };

        let _created: Option<User> = self
            .db
            .db
            .create(("mcp_auth", user_id))
            .content(user)
            .await?;

        println!("Created user read model for: {}", user_id);
        Ok(())
    }

    /// Update user OTP secret in the read model
    async fn update_user_otp_secret(
        &self,
        user_id: &str,
        email: &str,
        otp_secret: &str,
        otp_auth_url: &str,
    ) -> Result<(), EventStoreError> {
        use serde_json::Value;
        use std::collections::BTreeMap;
        let datetime = Utc::now();

        let mut update_data: BTreeMap<&str, Value> = BTreeMap::new();
        update_data.insert("otp_secret", Value::String(otp_secret.to_string()));
        update_data.insert("otp_auth_url", Value::String(otp_auth_url.to_string()));
        update_data.insert(
            "changed",
            Value::String(Datetime::from(datetime).to_string()),
        );

        let _updated: Option<User> = self
            .db
            .db
            .update(("mcp_auth", email))
            .merge(update_data)
            .await?;

        println!("Updated OTP secret for user: {} {}", user_id, email);
        Ok(())
    }

    /// Update user OTP status in the read model
    async fn update_user_otp_status(
        &self,
        user_id: &str,
        otp_enabled: bool,
        otp_verified: bool,
    ) -> Result<(), EventStoreError> {
        use serde_json::Value;
        use std::collections::BTreeMap;
        let datetime = Utc::now();

        let mut update_data: BTreeMap<&str, Value> = BTreeMap::new();
        update_data.insert("otp_enabled", Value::Bool(otp_enabled));
        update_data.insert("otp_verified", Value::Bool(otp_verified));
        update_data.insert(
            "changed",
            Value::String(Datetime::from(datetime).to_string()),
        );

        let _updated: Option<User> = self
            .db
            .db
            .update(("mcp_auth", user_id))
            .merge(update_data)
            .await?;

        println!("Updated OTP status for user: {}", user_id);
        Ok(())
    }

    /// Disable OTP for user in the read model
    async fn disable_user_otp(&self, user_id: &str) -> Result<(), EventStoreError> {
        use serde_json::Value;
        use std::collections::BTreeMap;
        let datetime = Utc::now();

        let mut update_data: BTreeMap<&str, Value> = BTreeMap::new();
        update_data.insert("otp_enabled", Value::Bool(false));
        update_data.insert("otp_verified", Value::Bool(false));
        update_data.insert("otp_secret", Value::Null);
        update_data.insert("otp_auth_url", Value::Null);
        update_data.insert(
            "changed",
            Value::String(Datetime::from(datetime).to_string()),
        );

        let _updated: Option<User> = self
            .db
            .db
            .update(("mcp_auth", user_id))
            .merge(update_data)
            .await?;

        println!("Disabled OTP for user: {}", user_id);
        Ok(())
    }

    /// Update last login timestamp
    async fn update_user_last_login(
        &self,
        user_id: &str,
        timestamp: &Datetime,
    ) -> Result<(), EventStoreError> {
        use serde_json::Value;
        use std::collections::BTreeMap;

        let mut update_data: BTreeMap<&str, Value> = BTreeMap::new();
        update_data.insert("changed", Value::String(timestamp.to_string()));

        let _updated: Option<User> = self
            .db
            .db
            .update(("mcp_auth", user_id))
            .merge(update_data)
            .await?;

        println!("Updated last login for user: {}", user_id);
        Ok(())
    }

    /// Rebuild all projections from events (useful for recovery or migration)
    pub async fn rebuild_projections(&self) -> Result<(), EventStoreError> {
        // First, clear the read model
        let _cleared: Vec<RecordId> = self.db.db.delete("mcp_auth").await?;

        // Get all events from event store
        let events: Vec<EventEnvelope> = self
            .db
            .db
            .query("SELECT * FROM events_store ORDER BY timestamp ASC")
            .await?
            .take(0)?;

        let events_count = events.len();

        // Replay all events to rebuild the read model
        for event in events {
            self.handle_event(&event).await?;
        }

        println!("Rebuilt all projections from {} events", events_count);
        Ok(())
    }
}
