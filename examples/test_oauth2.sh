#!/bin/bash

# OAuth2 Mock Server Test Script
# This script demonstrates the OAuth2 flow using curl commands

set -e

# Configuration
OAUTH2_SERVER="http://127.0.0.1:3000"
CLIENT_ID="test_client"
REDIRECT_URI="http://localhost:8080/callback"
SCOPE="read write"

echo "🚀 OAuth2 Mock Server Test Script"
echo "=================================="
echo

# Check if server is running
echo "1. Checking if OAuth2 Mock Server is running..."
if curl -s "$OAUTH2_SERVER/" > /dev/null; then
    echo "✅ Server is running!"
else
    echo "❌ Server is not running. Please start it with: cargo run"
    exit 1
fi

echo

# Get OpenID Connect configuration
echo "2. Getting OpenID Connect configuration..."
curl -s "$OAUTH2_SERVER/.well-known/openid_configuration" | jq '.' || {
    echo "❌ Failed to get OpenID Connect configuration"
    echo "Make sure jq is installed for JSON formatting"
    echo "You can install it with: sudo apt-get install jq (Ubuntu/Debian)"
    echo "Or: brew install jq (macOS)"
}

echo

# Create authorization URL
echo "3. Creating authorization URL..."
AUTH_URL="$OAUTH2_SERVER/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=$SCOPE&state=test_state_123"
echo "Authorization URL: $AUTH_URL"

echo

# Get authorization code (simulate user authorization)
echo "4. Getting authorization code..."
echo "Making request to authorization endpoint..."

# Make the request and extract the authorization code from the HTML response
RESPONSE=$(curl -s "$AUTH_URL")
if echo "$RESPONSE" | grep -q "Authorization Code Generated:"; then
    # Extract the authorization code using grep and sed
    AUTH_CODE=$(echo "$RESPONSE" | grep -A 1 'class="code"' | tail -n 1 | sed 's/<[^>]*>//g' | tr -d ' ')
    echo "✅ Authorization Code: $AUTH_CODE"
else
    echo "❌ Failed to get authorization code"
    exit 1
fi

echo

# Exchange authorization code for access token
echo "5. Exchanging authorization code for access token..."
TOKEN_RESPONSE=$(curl -s -X POST "$OAUTH2_SERVER/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=$AUTH_CODE&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI")

echo "Token Response:"
echo "$TOKEN_RESPONSE" | jq '.' || echo "$TOKEN_RESPONSE"

# Extract access token and refresh token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null || echo "")
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token' 2>/dev/null || echo "")

if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
    echo "✅ Access Token: $ACCESS_TOKEN"
    if [ -n "$REFRESH_TOKEN" ] && [ "$REFRESH_TOKEN" != "null" ]; then
        echo "✅ Refresh Token: $REFRESH_TOKEN"
    fi
else
    echo "❌ Failed to extract access token"
    exit 1
fi

echo

# Get user info using access token
echo "6. Getting user information..."
USERINFO_RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$OAUTH2_SERVER/userinfo")

echo "User Info Response:"
echo "$USERINFO_RESPONSE" | jq '.' || echo "$USERINFO_RESPONSE"

echo

# Test refresh token if available
if [ -n "$REFRESH_TOKEN" ] && [ "$REFRESH_TOKEN" != "null" ]; then
    echo "7. Testing refresh token..."
    REFRESH_RESPONSE=$(curl -s -X POST "$OAUTH2_SERVER/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=$CLIENT_ID")
    
    echo "Refresh Token Response:"
    echo "$REFRESH_RESPONSE" | jq '.' || echo "$REFRESH_RESPONSE"
    
    # Extract new access token
    NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token' 2>/dev/null || echo "")
    if [ -n "$NEW_ACCESS_TOKEN" ] && [ "$NEW_ACCESS_TOKEN" != "null" ]; then
        echo "✅ New Access Token: $NEW_ACCESS_TOKEN"
        
        # Test the new access token
        echo "8. Testing new access token..."
        NEW_USERINFO_RESPONSE=$(curl -s -H "Authorization: Bearer $NEW_ACCESS_TOKEN" "$OAUTH2_SERVER/userinfo")
        echo "New User Info Response:"
        echo "$NEW_USERINFO_RESPONSE" | jq '.' || echo "$NEW_USERINFO_RESPONSE"
    fi
fi

echo
echo "✅ OAuth2 Flow Test Complete!"
echo "============================="
