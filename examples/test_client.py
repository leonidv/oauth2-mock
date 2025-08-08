#!/usr/bin/env python3
"""
OAuth2 Mock Server Test Client

This script demonstrates how to interact with the OAuth2 mock server
to complete a full authorization flow.
"""

import requests
import webbrowser
import time
from urllib.parse import urlencode, parse_qs, urlparse

# Configuration
OAUTH2_SERVER = "http://127.0.0.1:3000"
CLIENT_ID = "test_client"
REDIRECT_URI = "http://localhost:8080/callback"
SCOPE = "read write"

def create_authorization_url():
    """Create the authorization URL for the OAuth2 flow."""
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'state': 'test_state_123'
    }
    
    auth_url = f"{OAUTH2_SERVER}/authorize?{urlencode(params)}"
    return auth_url

def exchange_code_for_token(code):
    """Exchange authorization code for access token."""
    token_url = f"{OAUTH2_SERVER}/token"
    
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    print(f"Exchanging code for token...")
    response = requests.post(token_url, data=data, headers=headers)
    
    if response.status_code == 200:
        token_data = response.json()
        print(f"✅ Token exchange successful!")
        print(f"Access Token: {token_data['access_token']}")
        print(f"Refresh Token: {token_data['refresh_token']}")
        print(f"Expires In: {token_data['expires_in']} seconds")
        return token_data
    else:
        print(f"❌ Token exchange failed: {response.status_code}")
        print(f"Response: {response.text}")
        return None

def get_user_info(access_token):
    """Get user information using the access token."""
    userinfo_url = f"{OAUTH2_SERVER}/userinfo"
    
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    print(f"Getting user info...")
    response = requests.get(userinfo_url, headers=headers)
    
    if response.status_code == 200:
        user_data = response.json()
        print(f"✅ User info retrieved successfully!")
        print(f"User ID: {user_data['sub']}")
        print(f"Name: {user_data['name']}")
        print(f"Email: {user_data['email']}")
        print(f"Email Verified: {user_data['email_verified']}")
        return user_data
    else:
        print(f"❌ Failed to get user info: {response.status_code}")
        print(f"Response: {response.text}")
        return None

def refresh_access_token(refresh_token):
    """Refresh the access token using a refresh token."""
    token_url = f"{OAUTH2_SERVER}/token"
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    print(f"Refreshing access token...")
    response = requests.post(token_url, data=data, headers=headers)
    
    if response.status_code == 200:
        token_data = response.json()
        print(f"✅ Token refresh successful!")
        print(f"New Access Token: {token_data['access_token']}")
        print(f"Expires In: {token_data['expires_in']} seconds")
        return token_data
    else:
        print(f"❌ Token refresh failed: {response.status_code}")
        print(f"Response: {response.text}")
        return None

def get_openid_configuration():
    """Get the OpenID Connect configuration."""
    config_url = f"{OAUTH2_SERVER}/.well-known/openid_configuration"
    
    print(f"Getting OpenID Connect configuration...")
    response = requests.get(config_url)
    
    if response.status_code == 200:
        config = response.json()
        print(f"✅ OpenID Connect configuration retrieved!")
        print(f"Issuer: {config['issuer']}")
        print(f"Authorization Endpoint: {config['authorization_endpoint']}")
        print(f"Token Endpoint: {config['token_endpoint']}")
        print(f"User Info Endpoint: {config['userinfo_endpoint']}")
        return config
    else:
        print(f"❌ Failed to get configuration: {response.status_code}")
        return None

def simulate_oauth_flow():
    """Simulate a complete OAuth2 flow."""
    print("🚀 Starting OAuth2 Flow Simulation")
    print("=" * 50)
    
    # Step 1: Get OpenID Connect configuration
    print("\n1. Getting OpenID Connect configuration...")
    config = get_openid_configuration()
    if not config:
        print("Failed to get configuration. Is the server running?")
        return
    
    # Step 2: Create authorization URL
    print("\n2. Creating authorization URL...")
    auth_url = create_authorization_url()
    print(f"Authorization URL: {auth_url}")
    
    # Step 3: Simulate user authorization
    print("\n3. Simulating user authorization...")
    print("In a real application, the user would be redirected to this URL.")
    print("For testing, we'll simulate the authorization by making a direct request.")
    
    # Make a direct request to get the authorization code
    response = requests.get(auth_url, allow_redirects=False)
    
    if response.status_code == 200:
        # Parse the HTML response to extract the authorization code
        # This is a simplified approach for testing
        html_content = response.text
        if 'Authorization Code Generated:' in html_content:
            # Extract the code from the HTML (this is a simple approach)
            lines = html_content.split('\n')
            for line in lines:
                if 'class="code"' in line:
                    # Extract the code from the HTML
                    start = line.find('class="code">') + len('class="code">')
                    end = line.find('</div>', start)
                    if start > 0 and end > start:
                        auth_code = line[start:end].strip()
                        break
            else:
                print("Could not extract authorization code from response")
                return
        else:
            print("Authorization page not found in response")
            return
    else:
        print(f"Failed to get authorization page: {response.status_code}")
        return
    
    print(f"Authorization Code: {auth_code}")
    
    # Step 4: Exchange code for token
    print("\n4. Exchanging authorization code for access token...")
    token_data = exchange_code_for_token(auth_code)
    if not token_data:
        return
    
    access_token = token_data['access_token']
    refresh_token = token_data.get('refresh_token')
    
    # Step 5: Get user info
    print("\n5. Getting user information...")
    user_data = get_user_info(access_token)
    if not user_data:
        return
    
    # Step 6: Test refresh token (if available)
    if refresh_token:
        print("\n6. Testing refresh token...")
        new_token_data = refresh_access_token(refresh_token)
        if new_token_data:
            # Test the new access token
            print("\n7. Testing new access token...")
            get_user_info(new_token_data['access_token'])
    
    print("\n✅ OAuth2 Flow Simulation Complete!")
    print("=" * 50)

def main():
    """Main function to run the OAuth2 flow simulation."""
    print("OAuth2 Mock Server Test Client")
    print("This script demonstrates the complete OAuth2 authorization flow.")
    print()
    
    # Check if server is running
    try:
        response = requests.get(f"{OAUTH2_SERVER}/", timeout=5)
        if response.status_code == 200:
            print("✅ OAuth2 Mock Server is running!")
        else:
            print("❌ OAuth2 Mock Server is not responding correctly")
            return
    except requests.exceptions.RequestException:
        print("❌ Cannot connect to OAuth2 Mock Server")
        print(f"Make sure the server is running on {OAUTH2_SERVER}")
        print("Run: cargo run")
        return
    
    print()
    simulate_oauth_flow()

if __name__ == "__main__":
    main()
