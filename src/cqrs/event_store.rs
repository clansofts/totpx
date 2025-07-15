use crate::cqrs::{EventEnvelope, UserEvent};
use crate::db::AppState;
use surrealdb::RecordId;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Event not found: {0}")]
    EventNotFound(String),
}

impl From<surrealdb::Error> for EventStoreError {
    fn from(err: surrealdb::Error) -> Self {
        EventStoreError::DatabaseError(err.to_string())
    }
}

impl From<serde_json::Error> for EventStoreError {
    fn from(err: serde_json::Error) -> Self {
        EventStoreError::SerializationError(err.to_string())
    }
}

/// Event Store responsible for persisting and retrieving events
pub struct EventStore {
    pub db: AppState,
}

impl EventStore {
    pub fn new(db: AppState) -> Self {
        Self { db }
    }

    /// Get the next event version for a specific aggregate
    pub async fn get_next_version(&self, aggregate_id: &str) -> Result<u64, EventStoreError> {
        let mut result = self
            .db
            .db
            .query("SELECT VALUE event_version FROM events_store WHERE aggregate_id = $aggregate_id ORDER BY event_version DESC LIMIT 1")
            .bind(("aggregate_id", aggregate_id.to_string()))
            .await?;

        let versions: Vec<u64> = result.take(0).map_err(|_| {
            EventStoreError::SerializationError("Result parsing failed".to_string())
        })?;

        if let Some(last_event) = versions.first() {
            Ok(last_event + 1)
        } else {
            Ok(1) // First event for this aggregate
        }
    }

    /// Save an event to the event store with proper versioning
    pub async fn save_event(&self, mut event: EventEnvelope) -> Result<(), EventStoreError> {
        // println!(
        //     "{{save_event}}: Generating OTP for user: {:?}",
        //     event.clone()
        // );
        // Get the next version for this aggregate
        let next_version = self.get_next_version(&event.aggregate_id).await?;
        event.event_version = next_version;
        // println!("Generating OTP for user: {:?}", event.clone());
        println!("save_event {:?}", event.clone());
        let _result: Option<EventEnvelope> = self
            .db
            .db
            .create("events_store")
            .content(event.clone())
            .await?;

        println!("Event saved: {:?}", _result.unwrap());
        Ok(())
    }

    /// Get all events for a specific aggregate
    pub async fn get_events_for_aggregate(
        &self,
        aggregate_id: String,
    ) -> Result<Vec<EventEnvelope>, EventStoreError> {
        let events: Vec<EventEnvelope> = self
            .db
            .db
            .query("SELECT * FROM events_store WHERE aggregate_id = $aggregate_id ORDER BY event_version ASC")
            .bind(("aggregate_id", aggregate_id))
            .await?
            .take(0)?;

        Ok(events)
    }

    /// Get all events of a specific type
    pub async fn get_events_by_type(
        &self,
        event_type: String,
    ) -> Result<Vec<EventEnvelope>, EventStoreError> {
        let events: Vec<EventEnvelope> = self
            .db
            .db
            .query("SELECT * FROM events_store WHERE event_data.event_type = $event_type ORDER BY timestamp ASC")
            .bind(("event_type", event_type))
            .await?
            .take(0)?;

        Ok(events)
    }

    /// Get all events (useful for replay/projection updates)
    pub async fn get_all_events(&self) -> Result<Vec<EventEnvelope>, EventStoreError> {
        let events: Vec<EventEnvelope> = self
            .db
            .db
            .query("SELECT * FROM events_store ORDER BY timestamp ASC")
            .await?
            .take(0)?;

        Ok(events)
    }

    /// Get events after a specific timestamp (useful for incremental updates)
    pub async fn get_events_after_timestamp(
        &self,
        timestamp: String,
    ) -> Result<Vec<EventEnvelope>, EventStoreError> {
        let events: Vec<EventEnvelope> = self
            .db
            .db
            .query("SELECT * FROM events_store WHERE timestamp > $timestamp ORDER BY timestamp ASC")
            .bind(("timestamp", timestamp))
            .await?
            .take(0)?;

        Ok(events)
    }

    /// Get events for an aggregate starting from a specific version
    pub async fn get_events_from_version(
        &self,
        aggregate_id: String,
        from_version: i32,
    ) -> Result<Vec<EventEnvelope>, EventStoreError> {
        let events: Vec<EventEnvelope> = self
            .db
            .db
            .query("SELECT * FROM events_store WHERE aggregate_id = $aggregate_id AND event_version >= $from_version ORDER BY event_version ASC")
            .bind(("aggregate_id", aggregate_id))
            .bind(("from_version", from_version))
            .await?
            .take(0)?;

        Ok(events)
    }

    /// Get the current version of an aggregate (useful for optimistic concurrency control)
    pub async fn get_current_version(&self, aggregate_id: &str) -> Result<u64, EventStoreError> {
        let mut result  = self
            .db
            .db
            .query("SELECT event_version FROM events_store WHERE aggregate_id = $aggregate_id ORDER BY event_version DESC LIMIT 1")
            .bind(("aggregate_id", aggregate_id.to_string()))
            .await?;

        let versions: Vec<u64> = result.take(0).map_err(|_| {
            EventStoreError::SerializationError("Result parsing failed".to_string())
        })?;

        if let Some(last_event) = versions.first() {
            Ok(last_event + 1)
        } else {
            Ok(1) // First event for this aggregate
        }
    }
}
