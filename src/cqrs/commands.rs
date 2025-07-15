use serde::{Deserialize, Serialize};

/// Commands represent actions that can be performed on the system
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command_type")]
pub enum UserCommand {
    RegisterUser {
        name: String,
        email: String,
        password: String,
    },
    LoginUser {
        email: String,
        password: String,
    },
    GenerateOtp {
        email: String,
        user_id: String,
    },
    VerifyOtp {
        user_id: String,
        token: String,
    },
    ValidateOtp {
        user_id: String,
        token: String,
    },
    DisableOtp {
        user_id: String,
    },
}

/// Command envelope that wraps commands with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEnvelope {
    pub command_id: String,
    pub aggregate_id: String,
    pub command_data: UserCommand,
}

impl CommandEnvelope {
    pub fn new(aggregate_id: String, command_data: UserCommand) -> Self {
        Self {
            command_id: uuid::Uuid::new_v4().to_string(),
            aggregate_id,
            command_data,
        }
    }
}
