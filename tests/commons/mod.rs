use axum_test::TestServer;
use oauth2_mock::{
    configuration::ApplicationConfiguration, router::setup_router, state::AppState,
    templates::Templates,
};

#[allow(dead_code)]
pub fn setup_server() -> TestServer {
    let cfg = ApplicationConfiguration::default();
    setup_server_with_config(cfg)
}

pub(super)  fn setup_server_with_config(config : ApplicationConfiguration) -> TestServer {
    let templates = Templates::load();
    let state = AppState::new(&config, templates);
    let app = setup_router(state);
    return TestServer::builder().save_cookies().build(app);
}
