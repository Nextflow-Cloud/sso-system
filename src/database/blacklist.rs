use mongodb::{bson::doc, Collection};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

static COLLECTION: OnceCell<Collection<Blacklist>> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Blacklist {
    pub token: String,
}

pub fn get_collection() -> Collection<Blacklist> {
    let collection = COLLECTION.get();
    if let Some(c) = collection {
        c.clone()
    } else {
        let c = super::get_database().collection::<Blacklist>("blacklist");
        COLLECTION
            .set(c.clone())
            .expect("Unexpected error: failed to set collection");
        c
    }
}
