use surrealdb::engine::remote::ws::{Client, Ws};
use surrealdb::opt::auth::Root;
use surrealdb::{Result as SurrealResult, Surreal};

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Surreal<Client>,
}

impl AppState {
    pub async fn init(
        address: String,
        username: String,
        secret: String,
        namespace: String,
        database: String,
    ) -> SurrealResult<AppState> {
        // Initialize SurrealDB
        let db = Surreal::new::<Ws>(address).await?;

        // Signin as a namespace, database, or root user
        db.signin(Root {
            username: username.as_str(),
            password: secret.as_str(),
        })
        .await?;

        // Select a specific namespace / database
        db.use_ns(namespace).use_db(database).await?;

        Ok(AppState { db: db })
    }
}
