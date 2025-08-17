# OAuth2 Mock Server

A lightweight OAuth2 authorization server mock built in Rust using Axum. 
This server is designed **only** for testing OAuth2 flows in development and testing environments.

Implements Authorization Code Flow

## Features

- **Authorization Code Flow**: Complete implementation of the OAuth2 authorization code grant type
- **Token Endpoint**: Exchange authorization codes for access tokens
- **Refresh Token Support**: Refresh expired access tokens
- **User Info Endpoint**: Retrieve user information specific to the authorized user
- **Configurable Users**: Load users from JSON configuration file with custom claims
- **Interactive User Selection**: Web interface to select users during authorization

## Quick Start

The server will start on `http://127.0.0.1:3000`

### Available Endpoints

- `GET /` - Login page. Click at user to login
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `GET /userinfo` - User info endpoint


