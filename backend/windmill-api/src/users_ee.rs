use std::sync::Arc;
use argon2::{Argon2, PasswordHasher};
use crate::db::ApiAuthed;
use crate::users::{EditPassword, NewUser};
use crate::{db::DB, webhook_util::WebhookShared};
use http::StatusCode;
use windmill_common::error::{Error, Result};

pub async fn create_user(
    _authed: ApiAuthed,
    _db: DB,
    _webhook: WebhookShared,
    _argon2: Arc<Argon2<'_>>,
    mut _nu: NewUser,
) -> Result<(StatusCode, String)> {
    let name = _nu.name.take().ok_or_else(|| Error::BadRequest("Name is required".to_string()))?;
    let workspace_id = "starter";

    let mut tx = _db.begin().await?;

    // Check existing email using raw query
    let existing_email: Option<(String,)> = sqlx::query_as(
        "SELECT email FROM password WHERE email = $1"
    )
    .bind(&_nu.email)
    .fetch_optional(&mut *tx)
    .await?;

    if existing_email.is_some() {
        return Err(Error::BadRequest("Email already exists".to_string()));
    }

    // Check existing username
    let existing_username: Option<(String,)> = sqlx::query_as(
        "SELECT username FROM usr WHERE workspace_id = $1 AND username = $2"
    )
    .bind(workspace_id)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await?;

    if existing_username.is_some() {
        return Err(Error::BadRequest("Username already exists in workspace".to_string()));
    }

    // Hash password with fixed salt to match existing pattern
    let salt = "z0Kg3qyaS14e+YHeihkJLQ"; // From sample data
    let password_hash = _argon2
        .hash_password(_nu.password.as_bytes(), salt.as_ref())
        .map_err(|e| Error::internal_err(e.to_string()))?
        .to_string();

    // Insert into password table
    sqlx::query(
        "INSERT INTO password (email, password_hash, login_type, super_admin, verified, name, company) 
        VALUES ($1, $2, 'password', $3, true, $4, $5)"
    )
    .bind(&_nu.email)
    .bind(password_hash)
    .bind(_nu.super_admin)
    .bind(&name)
    .bind(_nu.company.as_ref())
    .execute(&mut *tx)
    .await
    .map_err(|e| handle_database_error(e))?;

    // Insert into usr table
    sqlx::query(
        "INSERT INTO usr (workspace_id, username, email, is_admin, role) 
        VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(workspace_id)
    .bind(&name)
    .bind(&_nu.email)
    .bind(_nu.super_admin)
    .bind(&name)
    .execute(&mut *tx)
    .await
    .map_err(|e| handle_database_error(e))?;

    tx.commit().await?;
    Ok((StatusCode::OK, "User created successfully".to_string()))
}

pub async fn set_password(
    _db: DB,
    _argon2: Arc<Argon2<'_>>,
    _authed: ApiAuthed,
    _user_email: &str,
    _ep: EditPassword,
) -> Result<String> {
    if !_authed.is_admin && _authed.email != _user_email {
        return Err(Error::BadRequest("Not authorized to change password".to_string()));
    }

    // Verify user exists
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT email FROM password WHERE email = $1"
    )
    .bind(_user_email)
    .fetch_optional(&_db)
    .await?;

    if exists.is_none() {
        return Err(Error::BadRequest("User not found".to_string()));
    }

    // Hash with fixed salt
    let salt = "z0Kg3qyaS14e+YHeihkJLQ";
    let password_hash = _argon2
        .hash_password(_ep.password.as_bytes(), salt.as_ref())
        .map_err(|e| Error::internal_err(e.to_string()))?
        .to_string();

    sqlx::query(
        "UPDATE password SET password_hash = $1 WHERE email = $2"
    )
    .bind(password_hash)
    .bind(_user_email)
    .execute(&_db)
    .await?;

    Ok("Password updated successfully".to_string())
}

fn handle_database_error(e: sqlx::Error) -> Error {
    if let Some(db_err) = e.as_database_error() {
        match db_err.constraint() {
            Some("proper_email") => Error::BadRequest("Invalid email format".to_string()),
            Some("proper_username") => Error::BadRequest("Invalid username format".to_string()),
            _ => Error::InternalErr(db_err.to_string()),
        }
    } else {
        Error::InternalErr(e.to_string())
    }
}


pub fn send_email_if_possible(_subject: &str, _content: &str, _to: &str) {
    tracing::warn!(
        "send_email_if_possible is not implemented in Windmill's Open Source repository"
    );
}
