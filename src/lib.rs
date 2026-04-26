//! OAuth2 Mock Server
//! 
//! This library implements a mock OAuth2 server for testing purposes.
//! It provides a complete OAuth2 Authorization Code flow implementation that can be
//! used to test OAuth2 clients without requiring a real authorization server.
//! 
//! The server is structured as a collection of modules that handle different
//! aspects of the OAuth2 flow and server functionality.

/// Main application module containing the server implementation
pub mod application;

/// Configuration module for loading and managing server settings
pub mod configuration;

/// Template module for HTML response generation
pub mod templates;

/// State module managing application state and data storage
pub mod state;

/// Router module defining API endpoints and request handling
pub mod  router;

/// Access control module that handles authentication for the mock server itself
/// (not the OAuth2 client flow). Requires users to enter an access code to use
/// the mock server interface.
mod authorization;

/// OAuth2 protocol implementation including Authorization Code flow endpoints
mod oauth2;

