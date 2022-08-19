use mongodb::Collection;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

static COLLECTION: OnceCell<Collection<User>> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct User {
    pub id: String,
    pub email_hash: String,
    pub password_hash: String,
    pub username: String,
    pub display_name: String,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    // Recovery email, client-encrypted keys? 
}

pub fn get_collection() -> Collection<User> {
    let collection = COLLECTION.get();
    if let Some(c) = collection {
        c.clone()
    } else {
        let c = super::get_database().collection::<User>("users");
        COLLECTION.set(c.clone()).expect("Unexpected error: failed to set collection");
        c
    }
}
