
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    oauth2_mock::application::run().await?;
    Ok(())
}
