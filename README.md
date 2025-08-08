# OAuth2 Mock Server

A lightweight OAuth2 authorization server mock built in Rust using Axum. This server is designed for testing OAuth2 flows in development and testing environments.

## Features

- **Authorization Code Flow**: Complete implementation of the OAuth2 authorization code grant type
- **Token Endpoint**: Exchange authorization codes for access tokens
- **Refresh Token Support**: Refresh expired access tokens
- **User Info Endpoint**: Retrieve user information specific to the authorized user
- **OpenID Connect Discovery**: Well-known configuration endpoint
- **CORS Support**: Configured for cross-origin requests
- **Configurable Users**: Load users from TOML configuration file with custom claims
- **Interactive User Selection**: Web interface to select users during authorization
- **Custom Claims Support**: Add any claims to any user in the configuration
- **User Registration Display**: Home page shows all registered users
- **Template-Based UI**: Clean separation of HTML templates from application logic

## Quick Start

### Prerequisites

- Rust 1.70+ and Cargo

### Running the Server

1. Clone the repository:
```bash
git clone <repository-url>
cd oauth2-mock
```

2. Run the server with user configuration:
```bash
# Use default configuration file
cargo run

# Or specify a custom configuration file
cargo run -- --config config/users.toml
```

The server will start on `http://127.0.0.1:3000`

### Available Endpoints

- `GET /` - Home page with documentation
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `GET /userinfo` - User info endpoint
- `GET /.well-known/openid_configuration` - OpenID Connect configuration

## Testing the OAuth2 Flow

### 1. Authorization Request

Start the OAuth2 flow by redirecting users to the authorization endpoint:

```
GET http://127.0.0.1:3000/authorize?response_type=code&client_id=your_client_id&redirect_uri=http://localhost:8080/callback&scope=read&state=random_state
```

Parameters:
- `response_type`: Must be "code"
- `client_id`: Any string (not validated in mock)
- `redirect_uri`: Where to redirect after authorization
- `scope`: Optional scope (e.g., "read write")
- `state`: Optional state parameter for CSRF protection

### 2. Token Exchange

Exchange the authorization code for an access token:

```bash
curl -X POST http://127.0.0.1:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=YOUR_AUTH_CODE&client_id=your_client_id&redirect_uri=http://localhost:8080/callback"
```

Response:
```json
{
  "access_token": "22212a74-00c0-4042-9a57-3e4152fa37bb",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "d7a0aff4-376c-4cae-a72f-6c2cf6768b99",
  "scope": "read write"
}
```

### 3. User Info

Retrieve user information using the access token:

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://127.0.0.1:3000/userinfo
```

Response:
```json
{
  "sub": "mock_user_123",
  "name": "Mock User",
  "email": "mock@example.com",
  "email_verified": true,
  "picture": "https://via.placeholder.com/150"
}
```

### 4. Refresh Token

Refresh an expired access token:

```bash
curl -X POST http://127.0.0.1:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=your_client_id"
```

## OpenID Connect Configuration

The server provides OpenID Connect discovery at `/.well-known/openid_configuration`:

```bash
curl http://127.0.0.1:3000/.well-known/openid_configuration
```

This returns the server's configuration including supported endpoints, grant types, and scopes.

## Example Client Integration

### JavaScript/Node.js Example

```javascript
const axios = require('axios');

// Step 1: Redirect user to authorization endpoint
const authUrl = 'http://127.0.0.1:3000/authorize?' + new URLSearchParams({
  response_type: 'code',
  client_id: 'my_app',
  redirect_uri: 'http://localhost:8080/callback',
  scope: 'read write',
  state: 'random_state_123'
});

console.log('Redirect user to:', authUrl);

// Step 2: Exchange code for token (in your callback handler)
async function exchangeCodeForToken(code) {
  const response = await axios.post('http://127.0.0.1:3000/token', {
    grant_type: 'authorization_code',
    code: code,
    client_id: 'my_app',
    redirect_uri: 'http://localhost:8080/callback'
  }, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  
  return response.data;
}

// Step 3: Get user info
async function getUserInfo(accessToken) {
  const response = await axios.get('http://127.0.0.1:3000/userinfo', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  return response.data;
}
```

### Python Example

```python
import requests

# Step 1: Authorization URL
auth_params = {
    'response_type': 'code',
    'client_id': 'my_app',
    'redirect_uri': 'http://localhost:8080/callback',
    'scope': 'read write',
    'state': 'random_state_123'
}

auth_url = 'http://127.0.0.1:3000/authorize?' + '&'.join([f'{k}={v}' for k, v in auth_params.items()])
print(f"Redirect user to: {auth_url}")

# Step 2: Exchange code for token
def exchange_code_for_token(code):
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': 'my_app',
        'redirect_uri': 'http://localhost:8080/callback'
    }
    
    response = requests.post('http://127.0.0.1:3000/token', data=token_data)
    return response.json()

# Step 3: Get user info
def get_user_info(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get('http://127.0.0.1:3000/userinfo', headers=headers)
    return response.json()
```

## User Configuration

The OAuth2 mock server loads users from a TOML configuration file. Each user can have custom claims that will be returned by the userinfo endpoint.

### Configuration File Format

Create a TOML file (e.g., `config/users.toml`) with the following structure:

```toml
[users.user1]
login_id = "john.doe"
[users.user1.claims]
sub = "user_123"
name = "John Doe"
email = "john.doe@example.com"
email_verified = true
picture = "https://via.placeholder.com/150"
given_name = "John"
family_name = "Doe"
locale = "en-US"
zoneinfo = "America/New_York"

[users.user2]
login_id = "jane.smith"
[users.user2.claims]
sub = "user_456"
name = "Jane Smith"
email = "jane.smith@example.com"
email_verified = true
role = "admin"
department = "Engineering"
employee_id = "EMP789"
hire_date = "2023-01-15"
```

### Custom Claims

You can add any custom claims to users. Common OpenID Connect claims include:
- `sub` - Subject identifier (required)
- `name` - Full name
- `given_name` - First name
- `family_name` - Last name
- `email` - Email address
- `email_verified` - Boolean indicating if email is verified
- `picture` - Profile picture URL
- `locale` - User's locale
- `zoneinfo` - Timezone

You can also add custom claims like `role`, `department`, `employee_id`, etc.

### Running with Configuration

```bash
# Use default configuration file (config/users.toml)
cargo run

# Use custom configuration file
cargo run -- --config /path/to/your/users.toml
```

## Server Configuration

The server is configured with the following defaults:

- **Host**: 127.0.0.1
- **Port**: 3000
- **Token Expiry**: 1 hour
- **Authorization Code Expiry**: 10 minutes
- **Default Configuration File**: config/users.toml

## Security Notes

⚠️ **Important**: This is a mock server for testing purposes only. It does not implement proper security measures:

- No client authentication
- No PKCE validation
- No proper token validation
- No database persistence
- Accepts any authorization code or access token

Do not use this in production environments.

## Development

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Code Formatting

```bash
cargo fmt
```

### Linting

```bash
cargo clippy
```

## License

This project is open source and available under the MIT License.
