use anyhow::Result;
use rocket::serde::json::Json;
use securedrop_protocol::pki;
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
    let journalist_verifying_key =
        pki::load_verifying_key_from_bytes(request.journalist_key.as_bytes())?;
    // verify the key's signature
    pki::verify_intermediate_signature(
        journalist_verifying_key.as_bytes(),
        request.journalist_sig.as_bytes(),
    )?;
    let journalist_fetching_key =
        pki::load_public_key(request.journalist_fetching_key.as_bytes())?;
    pki::verify_intermediate_signature(
        journalist_fetching_key.as_bytes(),
        request.journalist_fetching_sig.as_bytes(),
    )?;
    // TODO figure out data storage
    todo!();
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, post_journalists])
}
