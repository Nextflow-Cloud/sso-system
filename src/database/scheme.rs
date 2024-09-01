use mongodb::{bson::doc, Collection};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

static COLLECTION: OnceCell<Collection<Scheme>> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Scheme {
    Opaque {
        user_id: String,
    },
    Passkey {
        user_id: String,
    }
}

pub fn get_collection() -> Collection<Scheme> {
    let collection = COLLECTION.get();
    if let Some(c) = collection {
        c.clone()
    } else {
        let c = super::get_database().collection::<Scheme>("schemes");
        COLLECTION
            .set(c.clone())
            .expect("Unexpected error: failed to set collection");
        c
    }
}
