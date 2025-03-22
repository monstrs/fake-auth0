use axum::body::Body;
use axum::response::IntoResponse;
use axum::{Json, http::StatusCode};
use axum::{Router, routing::get, routing::post};
use axum::{response::Response, http::Request, middleware::Next};
use axum_server::tls_rustls::RustlsConfig;
use serde::Serialize;
use std::{net::SocketAddr, path::PathBuf};
use uuid::Uuid;

#[derive(Serialize)]
pub struct User {
    pub user_id: String,
}

#[derive(Serialize)]
pub struct Role {
    pub id: String,
    pub name: String,
}

#[derive(Serialize)]
pub struct AssignUserRoleResponse {}

#[derive(Serialize)]
pub struct Token {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

pub async fn users_create() -> (StatusCode, Json<User>) {
    (
        StatusCode::OK,
        Json(User {
            user_id: Uuid::new_v4().to_string(),
        }),
    )
}

pub async fn roles_get() -> (StatusCode, Json<Vec<Role>>) {
    (
        StatusCode::OK,
        Json(vec![Role {
                id: Uuid::new_v4().to_string(),
                name: "TEAM".to_string(),
            }]),
        
    )
}

pub async fn user_assign_roles() -> (StatusCode, Json<AssignUserRoleResponse>) {
    (StatusCode::OK, Json(AssignUserRoleResponse {}))
}

pub async fn oauth_token_get() -> (StatusCode, Json<Token>) {
    (StatusCode::OK, Json(
        Token {
            access_token:"eyJz93a...k4laUWw".to_string(),
            token_type:"Bearer".to_string(),
            expires_in:86400
        }
    ))
}

pub async fn keys_private_get() -> String {
    include_str!("../keys/private-key.pem").to_string()
}

pub async fn keys_public_get() -> String {
    include_str!("../keys/public-key.pem").to_string()
}

pub async fn well_known_jwks_get() -> impl IntoResponse {
    (
        [("content-type", "application/json")],
        include_str!("../keys/jwks.json"),
    )
}

async fn uri_middleware<B>(request: Request<Body>, next: Next) -> Response {
    let uri = request.uri().clone();

    println!("uri: {}", uri);

    next.run(request).await
}

#[tokio::main]
async fn main() {
    let config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("cert.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("key.pem"),
    )
    .await
    .unwrap();

    let app = Router::new()
        .route("/api/v2/users", post(users_create))
        .route("/api/v2/roles", get(roles_get))
        .route("/api/v2/users/{id}/roles", post(user_assign_roles))
        .route("/oauth/token", post(oauth_token_get))
        .route("/keys/public", get(keys_public_get))
        .route("/keys/private", get(keys_private_get))
        .route("/.well-known/jwks.json", get(well_known_jwks_get))
        .layer(
            axum::middleware::from_fn(uri_middleware::<Body>)
        );

    println!("Fake AuthO: http://localhost:3000");

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
