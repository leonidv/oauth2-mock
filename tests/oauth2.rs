mod commons;

use axum::http::StatusCode;
use behave::prelude::*;
use std::collections::HashMap;
use yare::parameterized;

use commons::{setup_server, setup_server_with_config};
use oauth2_mock::configuration::ApplicationConfiguration;

#[tokio::test]
async fn custom_provider_paths_are_used_for_the_complete_flow() {
    let mut config = ApplicationConfiguration::default();
    config.oauth2.name = "Blitz Identity Provider".to_string();
    config.oauth2.authorization_path = "/blitz/oauth/ae".to_string();
    config.oauth2.token_path = "/blitz/oauth/te".to_string();
    config.oauth2.userinfo_path = "/blitz/oauth/me".to_string();
    config.oauth2.authorization_header_prefix = "OAuth".to_string();
    let server = setup_server_with_config(config);

    let home = server.get("/").await;
    home.assert_status_ok();
    home.assert_text_contains("Mocked provider: Blitz Identity Provider");
    home.assert_text_contains("GET /blitz/oauth/ae");
    home.assert_text_contains("POST /blitz/oauth/te");
    home.assert_text_contains("GET /blitz/oauth/me");
    home.assert_text_contains("Headers: Authorization: OAuth &lt;access_token&gt;");

    let authorization_url =
        "/blitz/oauth/ae?response_type=code&client_id=123&redirect_uri=http://localhost:8080";
    let login = server.get(authorization_url).await;
    login.assert_status_ok();
    login.assert_text_contains("/blitz/oauth/ae?login=admin");
    assert!(!login.text().contains("Blitz Identity Provider"));

    let authorization = server
        .get("/blitz/oauth/ae?login=admin&response_type=code&client_id=123&redirect_uri=http://localhost:8080")
        .await;
    authorization.assert_status(StatusCode::FOUND);
    let location = authorization
        .header("Location")
        .to_str()
        .expect("Location must be ASCII")
        .to_string();
    let redirect = url::Url::parse(&location).expect("valid redirect URL");
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization code");

    let response = server
        .post("/blitz/oauth/te")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
        ])
        .await;
    response.assert_status_ok();
    let json: serde_json::Value = response.json();
    let access_token = json["access_token"].as_str().expect("access token");

    server
        .get("/blitz/oauth/me")
        .add_header("Authorization", format!("OAuth {access_token}"))
        .await
        .assert_status_ok();

    server
        .get("/login?response_type=code&client_id=123&redirect_uri=http://localhost:8080")
        .await
        .assert_status_not_found();
    server.post("/token").await.assert_status_not_found();
    server.get("/userinfo").await.assert_status_not_found();
}

#[tokio::test]
async fn configured_authorization_path_can_use_legacy_authorize_path() {
    let mut config = ApplicationConfiguration::default();
    config.oauth2.authorization_path = "/authorize".to_string();
    let server = setup_server_with_config(config);

    server
        .get("/authorize?response_type=code&client_id=123&redirect_uri=http://localhost:8080")
        .await
        .assert_status_ok();
    server
        .get("/authorize?login=admin&response_type=code&client_id=123&redirect_uri=http://localhost:8080")
        .await
        .assert_status(StatusCode::FOUND);
}

#[tokio::test]
async fn code_token_and_info() -> Result<(), Box<dyn std::error::Error>> {
    let server = setup_server();
    let response = server
                .get("/authorize?login=admin&response_type=code&client_id=123&redirect_uri=http://localhost:8080?state=456")
                .await;

    // Check getting access code
    response
        .assert_status(StatusCode::FOUND)
        .assert_contains_header("Location");
    let header_value = response.header("Location");
    let location = header_value.to_str().expect("Failed to get Location value");
    let url = url::Url::parse(location).expect("Failed to parse Location URL");

    expect!(url.port()).to_be_some_with(8080)?;
    let url_exp = expect!(url.clone());
    url_exp.to_have_host("localhost")?;
    url_exp.to_have_query_param("code")?;
    url_exp.to_have_query_param_value("state", "456")?;

    let access_code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v)
        .unwrap();
    expect!(access_code.is_empty()).to_be_false().unwrap();

    // Check getting access token
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("code", &access_code);
    params.insert("redirect_uri", "http://localhost:8080");
    params.insert("client_id", "xxx");

    let response = server
        .post("/token")
        .form(&params)
        .content_type("application/x-www-form-urlencoded")
        .await;

    response
        .assert_status(StatusCode::OK)
        .assert_header("content-type", "application/json");

    let json: serde_json::Value = response.json();
    let json_expect = expect!(json.clone());
    json_expect.to_have_field("access_token")?;
    json_expect.to_have_field("refresh_token")?;
    json_expect.to_have_field_value("expires_in", &serde_json::Value::Number(3600.into()))?;

    let access_token = json
        .get("access_token")
        .unwrap()
        .as_str()
        .expect("Can't get value from field access_token ");

    // Get user's info
    let reponse = server
        .get("/userinfo")
        .authorization_bearer(access_token)
        .await;

    reponse.assert_status_ok();

    let json: serde_json::Value = reponse.json();
    let expected_userinfo: serde_json::Value = serde_json::from_str(
        r#"{
            "login": "admin",
            "id": "1",
            "first_name": "Michael",
            "last_name": "Johnson",
            "display_name": "Admin MJ",
            "default_email": "admin@company.com"
      }"#,
    )
    .unwrap();

    expect!(json).to_equal(expected_userinfo)?;
    Ok(())
}

#[parameterized(
    unauthorized_client = { "unauthorized_client" },
    access_denied = { "access_denied" },
    unsupported_response_type = { "unsupported_response_type" },
    invalid_scope = { "invalid_scope" },
    server_error = { "server_error" },
    temporarily_unavailable = { "temporarily_unavailable" }
)]
#[test_macro(tokio::test)]
async fn access_code_explicit_errors(error: &str) -> Result<(), Box<dyn std::error::Error>> {
    let server = setup_server();

    //let error = "unauthorized_client";
    let url = format!(
        "/authorize?error_type=access_code&error={error}\
        &response_type=code&client_id=123&redirect_uri=http://localhost:8080&state=456"
    );

    let response = server.get(&url).await;

    response.assert_status(StatusCode::FOUND);
    let header_value = response.header("Location");
    let location = header_value.to_str().expect("Failed to get Location value");
    let url = url::Url::parse(location).expect("Failed to parse Location URL");

    let url_expect = expect!(url.clone());
    url_expect.to_have_host("localhost")?;
    url_expect.to_have_query_param_value("error", error)?;
    url_expect.to_have_query_param_value("state", "456")?;

    Ok(())
}

/// Test explicit errors during access token retrieval
#[parameterized(
    invalid_request = { "invalid_request" },
    invalid_client = { "invalid_client" },
    invalid_grant = { "invalid_grant" },
    unauthorized_client = { "unauthorized_client" },
    unsupported_grant_type = { "unsupported_grant_type" },
    invalid_scope = { "invalid_scope" }
)]
#[test_macro(tokio::test)]
async fn access_token_explicit_errors(error: &str) -> Result<(), Box<dyn std::error::Error>> {
    //let error = "invalid_request";

    let server = setup_server();
    let url = format!(
        "/authorize?error_type=access_token&error={error}\
        &login=admin\
        &response_type=code&client_id=123&redirect_uri=http://localhost:8080&state=456"
    );

    let response = server.get(&url).await;

    response.assert_status(StatusCode::FOUND);
    let header_value = response.header("Location");
    let location = header_value.to_str().expect("Failed to get Location value");
    let url = url::Url::parse(location).expect("Failed to parse Location URL");

    let url_expect = expect!(url.clone());
    url_expect.to_have_host("localhost")?;
    url_expect.to_have_query_param("code")?;
    url_expect.to_have_query_param_value("state", "456")?;

    let access_code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v)
        .unwrap();
    expect!(access_code.is_empty()).to_be_false().unwrap();

    // Check getting access token
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("code", &access_code);
    params.insert("redirect_uri", "http://localhost:8080");
    params.insert("client_id", "xxx");

    let response = server
        .post("/token")
        .form(&params)
        .content_type("application/x-www-form-urlencoded")
        .await;

    response
        .assert_status(StatusCode::BAD_REQUEST)
        .assert_header("content-type", "application/json");

    let access_token_json: serde_json::Value = response.json();
    let json_expect = expect!(access_token_json);
    json_expect.to_have_field_value("error", &error.into())?;

    Ok(())
}

#[parameterized(
    missing_response_type = { "?client_id=123&redirect_uri=http://localhost", "response_type" },
    missing_client_id = { "?response_type=code&redirect_uri=http://localhost", "client_id" },
    missing_redirect_uri = { "?response_type=code&client_id=123", "redirect_uri" }
)]
#[test_macro(tokio::test)]
async fn authorize_missing_required_params(extra_params: &str, missing_field: &str) {
    let server = setup_server();
    let url = format!("/authorize{}", extra_params);
    let response = server.get(&url).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    // Failed to deserialize query string: missing field `response_type`
    let message = format!("Failed to deserialize query string: missing field `{missing_field}`");
    response.assert_text(&message);
}

#[parameterized(
    refresh_token = { "refresh_token" },
    client_credentials = { "client_credentials" },
    implicit = { "implicit" }
)]
#[test_macro(tokio::test)]
async fn token_unsupported_grant_type(grant_type: &str) {
    let server = setup_server();
    let mut params = HashMap::new();
    params.insert("grant_type", grant_type);
    params.insert("code", "xxx");

    let response = server
        .post("/token")
        .form(&params)
        .content_type("application/x-www-form-urlencoded")
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let json: serde_json::Value = response.json();
    assert_eq!(json["error"], "unsupported_grant_type");
}
