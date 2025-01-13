use anyhow::{anyhow, bail, Result};
use base64::prelude::*;
use rocket::{serde::json::Json, State};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use securedrop_protocol::{
    entity,
    pki::{self, PublicJournalist},
};
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate rocket;

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[get("/")]
fn index() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "OK",
        id: None,
        error: None,
    })
}
/// Base64-encoded journalist public keys + signature information
#[derive(Deserialize, Debug)]
struct AddJournalistRequest {
    journalist_key: String,
    journalist_sig: String,
    journalist_fetching_key: String,
    journalist_fetching_sig: String,
}

#[post("/journalist", data = "<request>")]
async fn post_journalist(
    db: &State<DatabaseConnection>,
    request: Json<AddJournalistRequest>,
) -> Json<StatusResponse> {
    let resp = match add_journalist(db, request.into_inner()).await {
        Ok(id) => StatusResponse {
            status: "OK",
            id: Some(id),
            error: None,
        },
        Err(err) => StatusResponse {
            status: "KO",
            id: None,
            error: Some(err.to_string()),
        },
    };
    Json(resp)
}

#[post("/journalist/<journalist_id>/ephemeral", data = "<request>")]
async fn post_journalist_ephemeral(
    db: &State<DatabaseConnection>,
    journalist_id: i32,
    request: Json<Vec<pki::PublicEphemeralKey>>,
) -> Json<StatusResponse> {
    let resp =
        match add_ephemeral(db, journalist_id, request.into_inner()).await {
            Ok(()) => StatusResponse {
                status: "OK",
                id: None,
                error: None,
            },
            Err(err) => StatusResponse {
                status: "KO",
                id: None,
                error: Some(err.to_string()),
            },
        };
    Json(resp)
}

async fn add_journalist(
    db: &DatabaseConnection,
    request: AddJournalistRequest,
) -> Result<i32> {
    // TODO: there's gotta be a simpler way to serde this instead of decoding everything manually
    let journalist = PublicJournalist {
        signing_key: BASE64_STANDARD
            .decode(request.journalist_key)?
            .as_slice()
            .try_into()?,
        signing_signature: BASE64_STANDARD
            .decode(request.journalist_sig)?
            .as_slice()
            .try_into()?,
        encrypting_key: BASE64_STANDARD
            .decode(request.journalist_fetching_key)?
            .as_slice()
            .try_into()?,
        encrypting_signature: BASE64_STANDARD
            .decode(request.journalist_fetching_sig)?
            .as_slice()
            .try_into()?,
    };

    // FIXME: these checks should be part of the PublicJournalist constructor
    pki::verify_intermediate_signature(
        &journalist.signing_key,
        &journalist.signing_signature,
    )?;
    pki::verify_intermediate_signature(
        &journalist.encrypting_key,
        &journalist.encrypting_signature,
    )?;
    // TODO: consider adding some uniqueness checks so that a journalist doesn't enroll multiple times
    // or accidentally reuse keys
    let journalist = entity::journalist::ActiveModel {
        keys: Set(serde_json::to_vec(&journalist)?),
        ..Default::default()
    };
    match journalist.insert(db).await {
        Ok(resp) => Ok(resp.id),
        Err(e) => Err(e.into()),
    }
}

async fn add_ephemeral(
    db: &DatabaseConnection,
    journalist_id: i32,
    ephemerals: Vec<pki::PublicEphemeralKey>,
) -> Result<()> {
    if ephemerals.len() > 100 {
        bail!("Can only register 100 ephemeral keys at a time");
    }
    let journalist = entity::journalist::Entity::find_by_id(journalist_id)
        .one(db)
        .await?
        .ok_or_else(|| anyhow!("Journalist not found"))?;
    let journo_key: PublicJournalist =
        serde_json::from_slice(&journalist.keys)?;
    for ephemeral in ephemerals {
        // Verify the signature on the ephemeral key
        // FIXME: make this a type-level check
        pki::verify_ephemeral_signature(&journo_key, &ephemeral)?;
        // TODO: need uniqueness checks
        // TODO: do we need any replay protection here?
        let model = entity::ephemeral_key::ActiveModel {
            journalist_id: Set(journalist_id),
            key: Set(serde_json::to_vec(&ephemeral)?),
            ..Default::default()
        };
        model.insert(db).await?;
    }
    Ok(())
}

#[launch]
async fn rocket() -> _ {
    let db = match securedrop_protocol::setup::set_up_db().await {
        Ok(db) => db,
        Err(e) => panic!("{}", e),
    };
    rocket::build().manage(db).mount(
        "/",
        routes![index, post_journalist, post_journalist_ephemeral],
    )
}
