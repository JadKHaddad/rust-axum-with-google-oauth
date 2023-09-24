// Code adapted from https://github.com/ramosbugs/oauth2-rs/blob/main/examples/google.rs
//
// Must set the enviroment variables:
// GOOGLE_CLIENT_ID=xxx
// GOOGLE_CLIENT_SECRET=yyy

use axum::{
    extract::{Extension, Host, Query, State, TypedHeader},
    headers::Cookie,
    response::{IntoResponse, Redirect},
};
use dotenvy::var;
use oauth2::{
    basic::BasicClient,
    reqwest::{async_http_client, http_client},
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RevocationUrl, Scope, TokenResponse, TokenUrl,
};

use chrono::Utc;
use openidconnect::{
    core::{
        CoreClaimName, CoreClient, CoreGenderClaim, CoreIdTokenClaims, CoreIdTokenVerifier,
        CoreProviderMetadata, CoreResponseType,
    },
    AdditionalClaims, AuthenticationFlow, IssuerUrl, LanguageTag, Nonce, UserInfoClaims,
};
use sqlx::SqlitePool;
use std::{collections::HashMap, env};
use uuid::Uuid;

use super::{AppError, UserData};

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    username: String,
    // policies: Vec<String>,
    // email: EndUserEmail, This is in standard
    // phone_number: EndUserPhoneNumber, This is also in standard
    groups: Vec<String>,
}
impl AdditionalClaims for Claims {}

fn get_client_(hostname: String) -> Result<BasicClient, AppError> {
    let google_client_id = ClientId::new(var("GOOGLE_CLIENT_ID")?);
    let google_client_secret = ClientSecret::new(var("GOOGLE_CLIENT_SECRET")?);
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .map_err(|_| "OAuth: invalid authorization endpoint URL")?;
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .map_err(|_| "OAuth: invalid token endpoint URL")?;

    let protocol = if hostname.starts_with("localhost") || hostname.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    };

    let redirect_url = format!("{}://{}/oauth_return", protocol, hostname);

    // Set up the config for the Google OAuth2 process.
    let client = BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).map_err(|_| "OAuth: invalid redirect URL")?)
    .set_revocation_uri(
        RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
            .map_err(|_| "OAuth: invalid revocation endpoint URL")?,
    );
    Ok(client)
}

async fn get_client() -> Result<CoreClient, AppError> {
    let client_id = ClientId::new(var("CLIENT_ID")?);
    let gitlab_client_secret = ClientSecret::new(var("CLIENT_SECRET")?);
    let issuer_url = IssuerUrl::new(
        "http://192.168.178.97:8200/v1/identity/oidc/provider/my-provider".to_string(),
    )
    .map_err(|_| "OAuth: Invalid issuer URL")?;

    // Fetc OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
        .await
        .map_err(|_| "OAuth: Failed to discover OpenID Provider")?
        .set_scopes_supported(Some(vec![
            Scope::new("openid".to_string()),
            Scope::new("groups".to_string()),
            Scope::new("user".to_string()),
        ]))
        .set_claims_supported(Some(vec![
            // Providers may also define an enum instead of using CoreClaimName.
            CoreClaimName::new("sub".to_string()),
            CoreClaimName::new("email".to_string()),
            CoreClaimName::new("username".to_string()),
            CoreClaimName::new("phone_number".to_string()),
            CoreClaimName::new("groups".to_string()),
        ]));

    // Set up the config for OAuth2 process.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        client_id,
        Some(gitlab_client_secret),
    )
    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_uri(
        RedirectUrl::new("http://192.168.178.97:3011/oauth_return".to_string())
            .map_err(|_| "OAuth: Invalid redirect URL")?,
    );

    Ok(client)
}

pub async fn login(
    Extension(user_data): Extension<Option<UserData>>,
    Query(mut params): Query<HashMap<String, String>>,
    State(db_pool): State<SqlitePool>,
) -> Result<Redirect, AppError> {
    if user_data.is_some() {
        // check if already authenticated
        return Ok(Redirect::to("/"));
    }

    let return_url = params
        .remove("return_url")
        .unwrap_or_else(|| "/".to_string());
    // TODO: check if return_url is valid

    let client = get_client().await?;

    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // This example is requesting access to the the user's profile including email.
        .add_scope(Scope::new("groups".to_string()))
        .add_scope(Scope::new("user".to_string()))
        .add_claims_locale(LanguageTag::new("email".to_string()))
        .add_claims_locale(LanguageTag::new("username".to_string()))
        .add_claims_locale(LanguageTag::new("phone_number".to_string()))
        .add_claims_locale(LanguageTag::new("groups".to_string()))
        .url();

    println!("insert");
    sqlx::query(
        "INSERT INTO oauth2_state_storage (csrf_state, nonce, return_url) VALUES (?, ?, ?);",
    )
    .bind(csrf_state.secret())
    .bind(nonce.secret())
    .bind(return_url)
    .execute(&db_pool)
    .await?;
    println!("inserted");

    Ok(Redirect::to(authorize_url.as_str()))
}

pub async fn login_(
    Extension(user_data): Extension<Option<UserData>>,
    Query(mut params): Query<HashMap<String, String>>,
    State(db_pool): State<SqlitePool>,
    Host(hostname): Host,
) -> Result<Redirect, AppError> {
    if user_data.is_some() {
        // check if already authenticated
        return Ok(Redirect::to("/"));
    }

    let return_url = params
        .remove("return_url")
        .unwrap_or_else(|| "/".to_string());
    // TODO: check if return_url is valid

    let client = get_client_(hostname)?;

    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
        ))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    sqlx::query(
        "INSERT INTO oauth2_state_storage (csrf_state, pkce_code_verifier, return_url) VALUES (?, ?, ?);",
    )
    .bind(csrf_state.secret())
    .bind(pkce_code_verifier.secret())
    .bind(return_url)
    .execute(&db_pool)
    .await?;

    Ok(Redirect::to(authorize_url.as_str()))
}

pub async fn oauth_return(
    Query(mut params): Query<HashMap<String, String>>,
    State(db_pool): State<SqlitePool>,
) -> Result<impl IntoResponse, AppError> {
    let state = CsrfToken::new(params.remove("state").ok_or("OAuth: without state")?);
    let code = AuthorizationCode::new(params.remove("code").ok_or("OAuth: without code")?);

    println!("delete");
    let query: (String, String) = sqlx::query_as(
        r#"DELETE FROM oauth2_state_storage WHERE csrf_state = ? RETURNING nonce,return_url"#,
    )
    .bind(state.secret())
    .fetch_one(&db_pool)
    .await?;
    println!("deleted");

    let nonce = query.0;
    let return_url = query.1;

    // Alternative:
    // let query: (String, String) = sqlx::query_as(
    //     r#"SELECT pkce_code_verifier,return_url FROM oauth2_state_storage WHERE csrf_state = ?"#,
    // )
    // .bind(state.secret())
    // .fetch_one(&db_pool)
    // .await?;
    // let _ = sqlx::query("DELETE FROM oauth2_state_storage WHERE csrf_state = ?")
    //     .bind(state.secret())
    //     .execute(&db_pool)
    //     .await;

    let client = get_client().await?;
    // Exchange the code with a token.
    let token_response = client
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .map_err(|_| "OAuth: Failed to contact token endpoint")?;

    // let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    // let nonce = Nonce::new(nonce);
    // let id_token_claims: &CoreIdTokenClaims = token_response
    //     .extra_fields()
    //     .id_token()
    //     .ok_or("OAuth: Server did not return an ID token")?
    //     .claims(&id_token_verifier, &nonce)
    //     .map_err(|_| "OAuth: Failed to verify ID token")?;

    let access_token = token_response.access_token().to_owned();

    let userinfo_claims: UserInfoClaims<Claims, CoreGenderClaim> = client
        .user_info(access_token, None)
        .map_err(|_| "OAuth: No user info endpoint")?
        .request(http_client)
        .map_err(|_| "OAuth: Failed requesting user info")?;

    let email = userinfo_claims
        .email()
        .to_owned()
        .map(|s| s.to_string())
        .ok_or("Auth: No email")?;

    // Check if user exists in database
    // If not, create a new user
    let query: Result<(i64,), _> = sqlx::query_as(r#"SELECT id FROM users WHERE email=?"#)
        .bind(email.as_str())
        .fetch_one(&db_pool)
        .await;
    let user_id = if let Ok(query) = query {
        query.0
    } else {
        let query: (i64,) = sqlx::query_as("INSERT INTO users (email) VALUES (?) RETURNING id")
            .bind(email.as_str())
            .fetch_one(&db_pool)
            .await?;
        query.0
    };

    // Create a session for the user
    let session_token_p1 = Uuid::new_v4().to_string();
    let session_token_p2 = Uuid::new_v4().to_string();
    let session_token = [session_token_p1.as_str(), "_", session_token_p2.as_str()].concat();
    let headers = axum::response::AppendHeaders([(
        axum::http::header::SET_COOKIE,
        "session_token=".to_owned()
            + &*session_token
            + "; path=/; httponly; secure; samesite=strict",
    )]);
    let now = Utc::now().timestamp();

    sqlx::query(
        "INSERT INTO user_sessions
        (session_token_p1, session_token_p2, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?);",
    )
    .bind(session_token_p1)
    .bind(session_token_p2)
    .bind(user_id)
    .bind(now)
    .bind(now + 60 * 60 * 24)
    .execute(&db_pool)
    .await?;

    Ok((headers, Redirect::to(return_url.as_str())))
}

pub async fn oauth_return_(
    Query(mut params): Query<HashMap<String, String>>,
    State(db_pool): State<SqlitePool>,
    Host(hostname): Host,
) -> Result<impl IntoResponse, AppError> {
    let state = CsrfToken::new(params.remove("state").ok_or("OAuth: without state")?);
    let code = AuthorizationCode::new(params.remove("code").ok_or("OAuth: without code")?);

    let query: (String, String) = sqlx::query_as(
        r#"DELETE FROM oauth2_state_storage WHERE csrf_state = ? RETURNING pkce_code_verifier,return_url"#,
    )
    .bind(state.secret())
    .fetch_one(&db_pool)
    .await?;

    // Alternative:
    // let query: (String, String) = sqlx::query_as(
    //     r#"SELECT pkce_code_verifier,return_url FROM oauth2_state_storage WHERE csrf_state = ?"#,
    // )
    // .bind(state.secret())
    // .fetch_one(&db_pool)
    // .await?;
    // let _ = sqlx::query("DELETE FROM oauth2_state_storage WHERE csrf_state = ?")
    //     .bind(state.secret())
    //     .execute(&db_pool)
    //     .await;

    let pkce_code_verifier = query.0;
    let return_url = query.1;
    let pkce_code_verifier = PkceCodeVerifier::new(pkce_code_verifier);

    // Exchange the code with a token.
    let client = get_client_(hostname)?;
    let token_response = tokio::task::spawn_blocking(move || {
        client
            .exchange_code(code)
            .set_pkce_verifier(pkce_code_verifier)
            .request(http_client)
    })
    .await
    .map_err(|_| "OAuth: exchange_code failure")?
    .map_err(|_| "OAuth: tokio spawn blocking failure")?;
    let access_token = token_response.access_token().secret();

    // Get user info from Google
    let url =
        "https://www.googleapis.com/oauth2/v2/userinfo?oauth_token=".to_owned() + access_token;
    let body = reqwest::get(url)
        .await
        .map_err(|_| "OAuth: reqwest failed to query userinfo")?
        .text()
        .await
        .map_err(|_| "OAuth: reqwest received invalid userinfo")?;
    let mut body: serde_json::Value =
        serde_json::from_str(body.as_str()).map_err(|_| "OAuth: Serde failed to parse userinfo")?;
    let email = body["email"]
        .take()
        .as_str()
        .ok_or("OAuth: Serde failed to parse email address")?
        .to_owned();
    let verified_email = body["verified_email"]
        .take()
        .as_bool()
        .ok_or("OAuth: Serde failed to parse verified_email")?;
    if !verified_email {
        return Err(AppError::new("OAuth: email address is not verified".to_owned())
            .with_user_message("Your email address is not verified. Please verify your email address with Google and try again.".to_owned()));
    }

    // Check if user exists in database
    // If not, create a new user
    let query: Result<(i64,), _> = sqlx::query_as(r#"SELECT id FROM users WHERE email=?"#)
        .bind(email.as_str())
        .fetch_one(&db_pool)
        .await;
    let user_id = if let Ok(query) = query {
        query.0
    } else {
        let query: (i64,) = sqlx::query_as("INSERT INTO users (email) VALUES (?) RETURNING id")
            .bind(email)
            .fetch_one(&db_pool)
            .await?;
        query.0
    };

    // Create a session for the user
    let session_token_p1 = Uuid::new_v4().to_string();
    let session_token_p2 = Uuid::new_v4().to_string();
    let session_token = [session_token_p1.as_str(), "_", session_token_p2.as_str()].concat();
    let headers = axum::response::AppendHeaders([(
        axum::http::header::SET_COOKIE,
        "session_token=".to_owned()
            + &*session_token
            + "; path=/; httponly; secure; samesite=strict",
    )]);
    let now = Utc::now().timestamp();

    sqlx::query(
        "INSERT INTO user_sessions
        (session_token_p1, session_token_p2, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?);",
    )
    .bind(session_token_p1)
    .bind(session_token_p2)
    .bind(user_id)
    .bind(now)
    .bind(now + 60 * 60 * 24)
    .execute(&db_pool)
    .await?;

    Ok((headers, Redirect::to(return_url.as_str())))
}

pub async fn logout(
    cookie: Option<TypedHeader<Cookie>>,
    State(db_pool): State<SqlitePool>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(cookie) = cookie {
        if let Some(session_token) = cookie.get("session_token") {
            let session_token: Vec<&str> = session_token.split('_').collect();
            let _ = sqlx::query("DELETE FROM user_sessions WHERE session_token_1 = ?")
                .bind(session_token[0])
                .execute(&db_pool)
                .await;
        }
    }
    let headers = axum::response::AppendHeaders([(
        axum::http::header::SET_COOKIE,
        "session_token=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
    )]);
    Ok((headers, Redirect::to("/")))
}
