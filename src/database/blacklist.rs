// use std::time::{UNIX_EPOCH, SystemTime};

// use chrono::Utc;
use mongodb::{Collection, bson::doc};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

static COLLECTION: OnceCell<Collection<Blacklist>> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Blacklist {
    pub token: String,
    // pub expires: u64
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

// // Purges all expired blacklist entries.
// pub async fn purge_blacklist() -> bool { // ok go ahead :)
//     let collection = get_collection();
//     // let duration = SystemTime::now()
//     //                         .duration_since(UNIX_EPOCH).expect("Unexpected error: time went backwards");
//     let today = Utc::now();
//     let result = collection.delete_many(doc! {
//         "$lt": {
//             "expires": today
//         }
//     }, None).await; // <-- this
//     if result.is_ok() {
//         true
//     } else {
//         false
//     }
// }
