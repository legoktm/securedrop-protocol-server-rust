use anyhow::Result;
use base64::prelude::*;
use rocket::serde::json::Json;
use securedrop_protocol::pki::{self, PublicJournalist};
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

#[post("/journalists", data = "<request>")]
async fn post_journalists(
    request: Json<AddJournalistRequest>,
) -> Json<StatusResponse> {
    let resp = match add_journalist(request.into_inner()) {
        Ok(()) => StatusResponse { status: "OK" },
        Err(_) => StatusResponse { status: "KO" },
    };
    Json(resp)
}

fn add_journalist(request: AddJournalistRequest) -> Result<()> {
    let journalist = PublicJournalist {
        signing_key: BASE64_STANDARD
            .decode(request.journalist_key)?
            .as_slice()
            .try_into()?,
        signing_signature: BASE64_STANDARD.decode(request.journalist_sig)?,
        encrypting_key: BASE64_STANDARD
            .decode(request.journalist_fetching_key)?
            .as_slice()
            .try_into()?,
        encrypting_signature: BASE64_STANDARD
            .decode(request.journalist_fetching_sig)?,
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
    // TODO figure out data storage
    todo!();
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, post_journalists])
}
