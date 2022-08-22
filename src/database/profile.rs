use mongodb::Collection;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

static COLLECTION: OnceCell<Collection<UserProfile>> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserProfile {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub website: String,
    pub avatar: String,
}

pub fn get_collection() -> Collection<UserProfile> {
    let collection = COLLECTION.get();
    if let Some(c) = collection {
        c.clone()
    } else {
        let c = super::get_database().collection::<UserProfile>("profiles");
        COLLECTION
            .set(c.clone())
            .expect("Unexpected error: failed to set collection");
        c
    }
}
