use crate::commons::setup_server_with_config;
use axum::http::StatusCode;
use axum_test::TestServer;
use oauth2_mock::configuration::ApplicationConfiguration;

mod commons;

fn server_with_access_restriction(code: &str) -> TestServer {
    let mut cfg = ApplicationConfiguration::default();
    cfg.access_restriction.enabled = true;
    cfg.access_restriction.code = code.to_string();

    setup_server_with_config(cfg)
}

#[tokio::test]
async fn can_authorize_oauth2_without_access_code() {
    let response = server_with_access_restriction("123")
        .get("/authorize?response_type=code&client_id=123&redirect_uri=http://localhost:8080")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn access_restriction_positive_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Modify config to enable access restriction
    let server = server_with_access_restriction("correct123");

    let login_url = "/login?login=admin&response_type=code&client_id=123\
                &redirect_uri=http://localhost:8080";

    let response = server.get(&login_url).await;
    response.assert_status_ok();
    response.assert_text_contains("auth-form-login");
    response.assert_text_contains(login_url);

    let params = [
        ("access_code", "correct123"),
        (
            "return_to",
            login_url,
        ),
    ];
    let correct_code_response = server.post("/check_code").form(&params).await;
    correct_code_response.assert_status(StatusCode::SEE_OTHER);
    correct_code_response.assert_header("Location",login_url);
    correct_code_response.assert_contains_cookie("authorized");
    assert!(correct_code_response.cookie("authorized").value().ends_with("yes"));

    let allowed_authorize_response = server
        .get("/authorize?response_type=code&client_id=123&redirect_uri=http://localhost:8080")
        .await;

    allowed_authorize_response.assert_status(StatusCode::FOUND);

    Ok(())
}
