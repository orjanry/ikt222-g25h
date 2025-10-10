#!/usr/bin/env python3
"""
OAuth2 Testing Script
Tests the complete OAuth2 Authorization Code Flow
"""

import requests
from urllib.parse import urlparse, parse_qs

# Configuration
BASE_URL = "http://localhost:5000"
CLIENT_ID = "test_client_123"
CLIENT_SECRET = "test_secret_456"
REDIRECT_URI = "http://localhost:5000/callback"

def test_oauth2_flow():
    """
    Test the complete OAuth2 authorization code flow
    
    Note: This script requires manual intervention for the authorization step
    since it involves user login and approval through a browser.
    """
    
    print("=" * 60)
    print("OAuth2 Authorization Code Flow Test")
    print("=" * 60)
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    # Step 1: Register/Login a test user first
    print("\n[Step 1] Creating/logging in test user...")
    
    # Try to register
    register_data = {
        'username': 'oauth_test_user',
        'email': 'oauth@test.com',
        'password': 'TestPassword123'
    }
    
    response = session.post(f'{BASE_URL}/register', data=register_data, allow_redirects=False)
    
    # Login
    login_data = {
        'username': 'oauth_test_user',
        'password': 'TestPassword123'
    }
    
    response = session.post(f'{BASE_URL}/login', data=login_data, allow_redirects=True)
    
    if response.status_code == 200:
        print("✓ User logged in successfully")
    else:
        print(f"✗ Login failed: {response.status_code}")
        return
    
    # Step 2: Request authorization
    print("\n[Step 2] Requesting authorization...")
    
    auth_params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'state': 'test_state_123',
        'scope': 'read'
    }
    
    response = session.get(f'{BASE_URL}/auth', params=auth_params, allow_redirects=False)
    
    if response.status_code == 200:
        print("✓ Authorization page loaded")
    else:
        print(f"✗ Failed to load authorization page: {response.status_code}")
        return
    
    # Step 3: Approve authorization
    print("\n[Step 3] Approving authorization...")
    
    approve_data = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'state': 'test_state_123',
        'scope': 'read'
    }
    
    response = session.post(f'{BASE_URL}/approve_auth', data=approve_data, allow_redirects=False)
    
    if response.status_code == 302:  # Redirect
        redirect_url = response.headers['Location']
        print(f"✓ Authorization approved, redirect to: {redirect_url}")
        
        # Extract authorization code from redirect URL
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        
        if 'code' in query_params:
            auth_code = query_params['code'][0]
            print(f"✓ Authorization code obtained: {auth_code[:20]}...")
        else:
            print("✗ No authorization code in redirect URL")
            return
    else:
        print(f"✗ Authorization approval failed: {response.status_code}")
        return
    
    # Step 4: Exchange authorization code for access token
    print("\n[Step 4] Exchanging code for access token...")
    
    token_data = {
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    response = requests.post(f'{BASE_URL}/token', data=token_data)
    
    if response.status_code == 200:
        token_info = response.json()
        access_token = token_info.get('access_token')
        refresh_token = token_info.get('refresh_token')
        expires_in = token_info.get('expires_in')
        
        print("✓ Access token obtained successfully")
        print(f"  Access Token: {access_token[:20]}...")
        print(f"  Refresh Token: {refresh_token[:20]}...")
        print(f"  Expires in: {expires_in} seconds")
    else:
        print(f"✗ Token exchange failed: {response.status_code}")
        print(f"  Response: {response.text}")
        return
    
    # Step 5: Access protected resource
    print("\n[Step 5] Accessing protected resource...")
    
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    response = requests.get(f'{BASE_URL}/protected_resource', headers=headers)
    
    if response.status_code == 200:
        user_data = response.json()
        print("✓ Protected resource accessed successfully")
        print(f"  User ID: {user_data.get('user_id')}")
        print(f"  Username: {user_data.get('username')}")
        print(f"  Email: {user_data.get('email')}")
    else:
        print(f"✗ Failed to access protected resource: {response.status_code}")
        print(f"  Response: {response.text}")
        return
    
    # Step 6: Test with invalid token
    print("\n[Step 6] Testing with invalid token...")
    
    headers = {
        'Authorization': 'Bearer invalid_token_12345'
    }
    
    response = requests.get(f'{BASE_URL}/protected_resource', headers=headers)
    
    if response.status_code == 401:
        print("✓ Invalid token correctly rejected")
    else:
        print(f"✗ Expected 401 but got: {response.status_code}")
    
    print("\n" + "=" * 60)
    print("OAuth2 Flow Test Complete!")
    print("=" * 60)
    print("\nSummary:")
    print("✓ User authentication")
    print("✓ Authorization request")
    print("✓ Authorization approval")
    print("✓ Code exchange for token")
    print("✓ Protected resource access")
    print("✓ Invalid token rejection")

def test_brute_force_protection():
    """Test brute force protection on login endpoint"""
    
    print("\n" + "=" * 60)
    print("Brute Force Protection Test")
    print("=" * 60)
    
    print("\n[Test] Attempting multiple failed logins...")
    
    for i in range(5):
        response = requests.post(f'{BASE_URL}/login', data={
            'username': 'testuser',
            'password': f'wrongpassword{i}'
        })
        
        print(f"  Attempt {i+1}: Status {response.status_code}")
        
        if 'Account locked' in response.text or 'locked' in response.text.lower():
            print("✓ Account locked after multiple failed attempts")
            break
    
    print("\nBrute Force Protection Test Complete!")

if __name__ == '__main__':
    import sys
    
    print("OAuth2 and Security Testing Suite")
    print("Make sure the Flask app is running on http://localhost:5000\n")
    
    choice = input("Run tests? (1) OAuth2 Flow, (2) Brute Force Protection, (3) Both: ")
    
    if choice == '1':
        test_oauth2_flow()
    elif choice == '2':
        test_brute_force_protection()
    elif choice == '3':
        test_oauth2_flow()
        test_brute_force_protection()
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)