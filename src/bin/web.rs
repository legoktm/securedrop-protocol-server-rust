use anyhow::Result;
use base64::prelude::*;
use rocket::{serde::json::Json, State};
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
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
}

#[get("/")]
fn index() -> Json<StatusResponse> {
    Json(StatusResponse { status: "OK" })
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
        Ok(()) => StatusResponse { status: "OK" },
        Err(_) => StatusResponse { status: "KO" },
    };
    Json(resp)
}

async fn add_journalist(
    db: &DatabaseConnection,
    request: AddJournalistRequest,
) -> Result<()> {
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
    let journalist = entity::journalist::ActiveModel {
        keys: Set(serde_json::to_vec(&journalist)?),
        ..Default::default()
    };
    match journalist.insert(db).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[launch]
async fn rocket() -> _ {
    let db = match securedrop_protocol::setup::set_up_db().await {
        Ok(db) => db,
        Err(e) => panic!("{}", e),
    };
    rocket::build()
        .manage(db)
        .mount("/", routes![index, post_journalist])
}
