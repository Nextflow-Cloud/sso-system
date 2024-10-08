use mongodb::{bson::doc, Collection};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

static COLLECTION: OnceCell<Collection<Code>> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Code {
    pub code: String,
    pub user_id: String,
}

pub fn get_collection() -> Collection<Code> {
    let collection = COLLECTION.get();
    if let Some(c) = collection {
        c.clone()
    } else {
        let c = super::get_database().collection::<Code>("codes");
        COLLECTION
            .set(c.clone())
            .expect("Unexpected error: failed to set collection");
        c
    }
}
