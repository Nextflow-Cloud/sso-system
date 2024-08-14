use mongodb::{bson::doc, Collection};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::{
    environment::CDN_MONGODB_DATABASE,
    errors::{Error, Result},
};

use super::get_connection;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileMetadata {
    File,
    Text,
    Image { width: isize, height: isize },
    Video { width: isize, height: isize },
    Audio,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct File {
    pub id: String,
    pub store: String,
    pub filename: String,
    pub metadata: FileMetadata,
    pub content_type: String,
    pub size: isize,
    pub attached: bool,
    pub deleted: bool,
    pub flagged: bool,
}

pub static COLLECTION: OnceCell<Collection<File>> = OnceCell::new();

pub fn get_collection() -> Collection<File> {
    let collection = COLLECTION.get();
    if let Some(c) = collection {
        c.clone()
    } else {
        let c = get_connection()
            .database(&CDN_MONGODB_DATABASE)
            .collection("files");
        COLLECTION
            .set(c.clone())
            .expect("Unexpected error: failed to set collection");
        c
    }
}

impl File {
    pub async fn get(id: &String) -> Result<File> {
        get_collection()
            .find_one(doc! {
                "id": id,
                "deleted": false,
                "flagged": false
            })
            .await?
            .ok_or(Error::DatabaseError)
    }

    pub async fn attach(&self) -> Result<()> {
        get_collection()
            .update_one(
                doc! {
                    "id": &self.id,
                    "deleted": false,
                    "flagged": false,
                },
                doc! {
                    "$set": {
                        "attached": true,
                    },
                },
            )
            .await?;
        Ok(())
    }

    pub async fn detach(&self) -> Result<()> {
        get_collection()
            .update_one(
                doc! {
                    "id": &self.id,
                    "deleted": false,
                    "flagged": false,
                },
                doc! {
                    "$set": {
                        "attached": false,
                    },
                },
            )
            .await?;
        Ok(())
    }
}
