use std::sync::Arc;
use argon2::{Argon2, PasswordHash, PasswordHasher};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use sqlx::{Postgres, Transaction};
use windmill_common::error::Error;

use crate::db::ApiAuthed;
use crate::users::{EditPassword, NewUser};
use crate::{db::DB, webhook_util::WebhookShared};
use http::StatusCode;
use windmill_common::error::Result;

pub async fn create_user(
    _authed: ApiAuthed,
    _db: DB,
    _webhook: WebhookShared,
    _argon2: Arc<Argon2<'_>>,
    mut _nu: NewUser,
) -> Result<(StatusCode, String)> {
    let name = _nu.name.take().ok_or_else(|| Error::BadRequest("Name is required".to_string()))?;

    let workspace_id = "starter"; // Assuming workspace_id is 'starter'

    let mut tx = _db.begin().await?;

    // Check if email already exists in password table
    let existing_email: Option<String> = sqlx::query_scalar!(
        "SELECT email FROM password WHERE email = $1",
        _nu.email
    )
    .fetch_optional(&mut *tx)
    .await?;

    if existing_email.is_some() {
        return Err(Error::BadRequest("Email already exists".to_string()));
    }

    // Check if username already exists in the assumed workspace
    let existing_username: Option<String> = sqlx::query_scalar!(
        "SELECT username FROM usr WHERE workspace_id = $1 AND username = $2",
        workspace_id,
        name
    )
    .fetch_optional(&mut *tx)
    .await?;

    if existing_username.is_some() {
        return Err(Error::BadRequest("Username already exists in workspace".to_string()));
    }

    // Hash the password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = _argon2
        .hash_password(_nu.password.as_bytes(), &salt)
        .map_err(|e| Error::internal_err(e.to_string()))?
        .to_string();

    // Insert into password table
    let password_insert = sqlx::query!(
        "INSERT INTO password (email, password_hash, login_type, super_admin, verified, name, company) VALUES ($1, $2, 'password', $3, true, $4, $5)",
        _nu.email,
        password_hash,
        _nu.super_admin,
        name,
        _nu.company
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = password_insert {
        return Err(handle_database_error(e));
    }

    // Insert into usr table
    let usr_insert = sqlx::query!(
        "INSERT INTO usr (workspace_id, username, email, is_admin, role) VALUES ($1, $2, $3, $4, $5)",
        workspace_id,
        name,
        _nu.email,
        _nu.super_admin,
        name
    )
    .execute(&mut *tx)
    .await;

    match usr_insert {
        Ok(_) => {}
        Err(e) => {
            if let Some(db_err) = e.as_database_error() {
                match db_err.constraint() {
                    Some("proper_email") => return Err(Error::BadRequest("Invalid email format".to_string())),
                    Some("proper_username") => return Err(Error::BadRequest("Invalid username format".to_string())),
                    _ => return Err(Error::InternalErr(db_err.to_string())),
                }
            } else {
                return Err(Error::InternalErr(e.to_string()));
            }
        }
    }

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
    // Check authorization: either the same user or an admin
    if !_authed.is_admin && _authed.email != _user_email {
        return Err(Error::Forbidden("Not authorized to change this password".to_string()));
    }

    // Check if user exists
    let exists: Option<String> = sqlx::query_scalar!(
        "SELECT email FROM password WHERE email = $1",
        _user_email
    )
    .fetch_optional(&_db)
    .await?;

    if exists.is_none() {
        return Err(Error::BadRequest("User not found".to_string()));
    }

    // Hash the new password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = _argon2
        .hash_password(_ep.password.as_bytes(), &salt)
        .map_err(|e| Error::internal_err(e.to_string()))?
        .to_string();

    // Update password
    sqlx::query!(
        "UPDATE password SET password_hash = $1 WHERE email = $2",
        password_hash,
        _user_email
    )
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
