// mod api;
mod cqrs;
// mod cqrs_api;
mod cqrs_service;
mod db;
mod graphql;
mod models;
mod response;
mod services;

use async_graphql::http::{GraphQLPlaygroundConfig, playground_source};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::{
    db::AppState,
    graphql::{GraphQLContext, create_schema},
};

// GraphQL handlers
async fn graphql_handler(
    State(app_state): State<AppState>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let schema = create_schema();
    let context = GraphQLContext::new(app_state);
    schema.execute(req.into_inner().data(context)).await.into()
}

async fn graphql_playground() -> impl IntoResponse {
    Html(playground_source(GraphQLPlaygroundConfig::new("/graphql")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("Initializing Authentication Database Connection");
    let address = String::from("0.0.0.0:5555");
    let username = String::from("root");
    let secret = String::from("@Cr34f1n1ty");
    let namespace = String::from("malipo");
    let database = String::from("eventors");

    let app_state = AppState::init(address, username, secret, namespace, database)
        .await
        .expect("Failed to initialize database");
    // let app_state = db;

    println!("🚀 Server started successfully");

    let cors = CorsLayer::new()
        // .allow_origin("http://localhost:3000".parse::<axum::http::HeaderValue>()?)
        .allow_origin(Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/graphql", post(graphql_handler))
        .route("/", get(graphql_playground))
        .route("/playground", get(graphql_playground))
        // Keep REST API for backward compatibility if needed
        // .merge(cqrs_api::create_cqrs_router())
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors),
        )
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
