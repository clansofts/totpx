use crate::{
    cqrs::UserStats,
    cqrs_service::CqrsUserService,
    db::AppState,
    models::{
        DisableOTPSchema, GenerateOTPSchema, User, UserLoginSchema, UserRegisterSchema,
        VerifyOTPSchema,
    },
    response::{GenOtpResponse, UserData, UserResponse},
};
use async_graphql::*;

// GraphQL Input Types
#[derive(InputObject)]
pub struct RegisterUserInput {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(InputObject)]
pub struct LoginUserInput {
    pub email: String,
    pub password: String,
}

#[derive(InputObject)]
pub struct GenerateOtpInput {
    pub email: String,
    pub user_id: String,
}

#[derive(InputObject)]
pub struct VerifyOtpInput {
    pub user_id: String,
    pub token: String,
}

#[derive(InputObject)]
pub struct ValidateOtpInput {
    pub user_id: String,
    pub token: String,
}

#[derive(InputObject)]
pub struct DisableOtpInput {
    pub user_id: String,
}

// GraphQL Output Types
#[derive(SimpleObject)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
}

#[derive(SimpleObject)]
pub struct LoginResponse {
    pub success: bool,
    pub message: Option<String>,
    pub user: Option<GraphQLUserData>,
}

#[derive(SimpleObject, Clone)]
pub struct GraphQLUserData {
    pub id: String,
    pub username: String,
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

impl From<UserData> for GraphQLUserData {
    fn from(user_data: UserData) -> Self {
        Self {
            id: user_data.id,
            username: user_data.username,
            category: user_data.category,
            stakeholder: user_data.stakeholder,
            status: user_data.status,
            expired: user_data.expired,
            verified: user_data.verified,
            otp_secret: user_data.otp_secret,
            otp_auth_url: user_data.otp_auth_url,
            otp_enabled: user_data.otp_enabled,
            otp_verified: user_data.otp_verified,
            stamp: user_data.stamp,
            changed: user_data.changed,
        }
    }
}

impl From<User> for GraphQLUserData {
    fn from(user: User) -> Self {
        Self {
            id: user.id.map_or("".to_string(), |id| id.to_string()),
            username: user.username,
            category: user.category,
            stakeholder: user.stakeholder,
            status: user.status,
            expired: user.expired.unwrap_or(false),
            verified: user.verified.unwrap_or(false),
            otp_secret: user.otp_secret,
            otp_auth_url: user.otp_auth_url,
            otp_enabled: user.otp_enabled.unwrap_or(false),
            otp_verified: user.otp_verified.unwrap_or(false),
            stamp: user.stamp.map_or("".to_string(), |s| s.to_string()),
            changed: user.changed.map_or("".to_string(), |c| c.to_string()),
        }
    }
}

#[derive(SimpleObject)]
pub struct GenerateOtpResponse {
    pub success: bool,
    pub message: Option<String>,
    pub base32_secret: Option<String>,
    pub otp_auth_url: Option<String>,
}

#[derive(SimpleObject)]
pub struct VerifyOtpResponse {
    pub success: bool,
    pub message: Option<String>,
    pub user: Option<GraphQLUserData>,
}

#[derive(SimpleObject)]
pub struct ValidateOtpResponse {
    pub success: bool,
    pub valid: bool,
    pub message: Option<String>,
}

#[derive(SimpleObject)]
pub struct DisableOtpResponse {
    pub success: bool,
    pub message: Option<String>,
    pub user: Option<GraphQLUserData>,
}

#[derive(SimpleObject)]
pub struct UsersResponse {
    pub success: bool,
    pub users: Vec<GraphQLUserData>,
    pub message: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct GraphQLUserStats {
    pub total_users: i64,
    pub users_with_otp: i64,
    pub users_verified: i64,
}

impl From<UserStats> for GraphQLUserStats {
    fn from(stats: UserStats) -> Self {
        Self {
            total_users: stats.total_users,
            users_with_otp: stats.users_with_otp_enabled,
            users_verified: stats.users_with_otp_verified,
        }
    }
}

#[derive(SimpleObject)]
pub struct UserStatsResponse {
    pub success: bool,
    pub stats: Option<GraphQLUserStats>,
    pub message: Option<String>,
}

// GraphQL Context
#[derive(Clone)]
pub struct GraphQLContext {
    pub app_state: AppState,
}

impl GraphQLContext {
    pub fn new(app_state: AppState) -> Self {
        Self { app_state }
    }
}

// Query Resolver
pub struct Query;

#[Object]
impl Query {
    /// Get application health status
    async fn health(&self) -> &str {
        "CQRS-based Two-Factor Authentication (2FA) in Rust with Event Sourcing via GraphQL"
    }

    /// Get user by ID
    async fn user(&self, ctx: &Context<'_>, user_id: String) -> Result<Option<GraphQLUserData>> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        match service.get_user_by_id(&user_id).await {
            Ok(Some(user)) => Ok(Some(GraphQLUserData::from(user))),
            Ok(None) => Ok(None),
            Err(_) => Err("Failed to fetch user".into()),
        }
    }

    /// Get user by email
    async fn user_by_email(
        &self,
        ctx: &Context<'_>,
        email: String,
    ) -> Result<Option<GraphQLUserData>> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        match service.get_user_by_email(&email).await {
            Ok(Some(user)) => Ok(Some(GraphQLUserData::from(user))),
            Ok(None) => Ok(None),
            Err(_) => Err("Failed to fetch user".into()),
        }
    }

    /// Get all users
    async fn users(&self, ctx: &Context<'_>) -> Result<UsersResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        match service.get_all_users().await {
            Ok(users) => {
                let graphql_users: Vec<GraphQLUserData> =
                    users.into_iter().map(GraphQLUserData::from).collect();

                Ok(UsersResponse {
                    success: true,
                    users: graphql_users,
                    message: None,
                })
            }
            Err(_) => Ok(UsersResponse {
                success: false,
                users: vec![],
                message: Some("Failed to fetch users".to_string()),
            }),
        }
    }

    /// Get users with OTP enabled
    async fn users_with_otp_enabled(&self, ctx: &Context<'_>) -> Result<UsersResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        match service.get_users_with_otp_enabled().await {
            Ok(users) => {
                let graphql_users: Vec<GraphQLUserData> =
                    users.into_iter().map(GraphQLUserData::from).collect();

                Ok(UsersResponse {
                    success: true,
                    users: graphql_users,
                    message: None,
                })
            }
            Err(_) => Ok(UsersResponse {
                success: false,
                users: vec![],
                message: Some("Failed to fetch users with OTP enabled".to_string()),
            }),
        }
    }

    /// Get user statistics
    async fn user_stats(&self, ctx: &Context<'_>) -> Result<UserStatsResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        match service.get_user_stats().await {
            Ok(stats) => Ok(UserStatsResponse {
                success: true,
                stats: Some(GraphQLUserStats::from(stats)),
                message: None,
            }),
            Err(_) => Ok(UserStatsResponse {
                success: false,
                stats: None,
                message: Some("Failed to fetch user statistics".to_string()),
            }),
        }
    }
}

// Mutation Resolver
pub struct Mutation;

#[Object]
impl Mutation {
    /// Register a new user
    async fn register_user(
        &self,
        ctx: &Context<'_>,
        input: RegisterUserInput,
    ) -> Result<RegisterResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        let schema = UserRegisterSchema {
            name: input.name,
            email: input.email,
            password: input.password,
        };

        match service.register_user(&schema).await {
            Ok(message) => Ok(RegisterResponse {
                success: true,
                message,
            }),
            Err(_) => Ok(RegisterResponse {
                success: false,
                message: "Registration failed".to_string(),
            }),
        }
    }

    /// Login user
    async fn login_user(&self, ctx: &Context<'_>, input: LoginUserInput) -> Result<LoginResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        let schema = UserLoginSchema {
            email: input.email,
            password: input.password,
        };

        match service.login_user(&schema).await {
            Ok(user_response) => Ok(LoginResponse {
                success: true,
                message: Some(user_response.status),
                user: Some(GraphQLUserData::from(user_response.user)),
            }),
            Err(_) => Ok(LoginResponse {
                success: false,
                message: Some("Login failed".to_string()),
                user: None,
            }),
        }
    }

    /// Generate OTP for user
    async fn generate_otp(
        &self,
        ctx: &Context<'_>,
        input: GenerateOtpInput,
    ) -> Result<GenerateOtpResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        let schema = GenerateOTPSchema {
            email: input.email,
            user_id: input.user_id,
        };

        match service.generate_otp(&schema).await {
            Ok((base32_secret, otp_auth_url)) => Ok(GenerateOtpResponse {
                success: true,
                message: None,
                base32_secret: Some(base32_secret),
                otp_auth_url: Some(otp_auth_url),
            }),
            Err(_) => Ok(GenerateOtpResponse {
                success: false,
                message: Some("Failed to generate OTP".to_string()),
                base32_secret: None,
                otp_auth_url: None,
            }),
        }
    }

    /// Verify OTP
    async fn verify_otp(
        &self,
        ctx: &Context<'_>,
        input: VerifyOtpInput,
    ) -> Result<VerifyOtpResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        let schema = VerifyOTPSchema {
            user_id: input.user_id,
            token: input.token,
        };

        match service.verify_otp(&schema).await {
            Ok(user_data) => Ok(VerifyOtpResponse {
                success: true,
                message: None,
                user: Some(GraphQLUserData::from(user_data)),
            }),
            Err(_) => Ok(VerifyOtpResponse {
                success: false,
                message: Some("OTP verification failed".to_string()),
                user: None,
            }),
        }
    }

    /// Validate OTP
    async fn validate_otp(
        &self,
        ctx: &Context<'_>,
        input: ValidateOtpInput,
    ) -> Result<ValidateOtpResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        let schema = VerifyOTPSchema {
            user_id: input.user_id,
            token: input.token,
        };

        match service.validate_otp(&schema).await {
            Ok(is_valid) => Ok(ValidateOtpResponse {
                success: true,
                valid: is_valid,
                message: None,
            }),
            Err(_) => Ok(ValidateOtpResponse {
                success: false,
                valid: false,
                message: Some("OTP validation failed".to_string()),
            }),
        }
    }

    /// Disable OTP for user
    async fn disable_otp(
        &self,
        ctx: &Context<'_>,
        input: DisableOtpInput,
    ) -> Result<DisableOtpResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let service = CqrsUserService::new(context.app_state.clone());

        let schema = DisableOTPSchema {
            user_id: input.user_id,
        };

        match service.disable_otp(&schema).await {
            Ok(user_data) => Ok(DisableOtpResponse {
                success: true,
                message: None,
                user: Some(GraphQLUserData::from(user_data)),
            }),
            Err(_) => Ok(DisableOtpResponse {
                success: false,
                message: Some("Failed to disable OTP".to_string()),
                user: None,
            }),
        }
    }
}

// Schema type
pub type TotpSchema = Schema<Query, Mutation, EmptySubscription>;

pub fn create_schema() -> TotpSchema {
    Schema::build(Query, Mutation, EmptySubscription).finish()
}
