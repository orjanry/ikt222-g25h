#!/usr/bin/env python3
"""
Script to populate the database with sample data for Assignment 2
Updated to use Werkzeug password hashing
"""

import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

def hash_password(password):
    """Hash password using Werkzeug PBKDF2"""
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def populate_database():
    # Connect to database
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # Create sample users with Werkzeug password hashes
    users = [
        ('admin', 'admin123', 'admin@example.com', False),
        ('john_doe', 'password123', 'john@example.com', False),
        ('jane_smith', 'mypassword', 'jane@example.com', True),  # This user has 2FA enabled
    ]
    
    print("Creating sample users...")
    for username, password, email, has_2fa in users:
        try:
            # Generate TOTP secret for users with 2FA
            totp_secret = None
            if has_2fa:
                import pyotp
                totp_secret = pyotp.random_base32()
            
            c.execute('''INSERT INTO users 
                         (username, password_hash, email, totp_secret, totp_enabled) 
                         VALUES (?, ?, ?, ?, ?)''',
                     (username, hash_password(password), email, totp_secret, 1 if has_2fa else 0))
            
            if has_2fa:
                print(f"Created user: {username} (2FA enabled)")
                print(f"2FA Secret: {totp_secret}")
            else:
                print(f"Created user: {username}")
        except sqlite3.IntegrityError:
            print(f"- User {username} already exists")
    
    # Get user IDs
    c.execute('SELECT id, username FROM users')
    user_dict = {row[1]: row[0] for row in c.fetchall()}
    
    # Create sample posts
    posts = [
        ('Welcome to the Enhanced Blog', 
         'This blog now includes advanced authentication features: OAuth2, 2FA, and brute force protection!', 
         'admin'),
        ('Understanding Web Security', 
         'Web security is crucial. This app demonstrates Werkzeug password hashing, rate limiting, and two-factor authentication.', 
         'john_doe'),
        ('OAuth2 Explained', 
         'OAuth2 allows secure delegated access without sharing passwords. This blog implements the Authorization Code Flow.', 
         'jane_smith'),
        ('Two-Factor Authentication Guide', 
         'Enable 2FA for enhanced security. Use Google Authenticator to scan the QR code during registration.', 
         'admin'),
        ('Testing Security Features', 
         'Try testing: brute force protection (3 failed logins), 2FA setup, and OAuth2 authorization flow.', 
         'john_doe'),
        ('Assignment 2 Complete!', 
         'This application fulfills all 5 requirements: Database Integration, Authentication, Brute Force Protection, 2FA, and OAuth2.', 
         'jane_smith'),
    ]
    
    print("\nCreating sample posts...")
    for title, content, author in posts:
        if author in user_dict:
            c.execute('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
                     (title, content, user_dict[author]))
            print(f"Created post: {title}")
    
    # Get post IDs for comments
    c.execute('SELECT id, title FROM posts')
    post_dict = {row[1]: row[0] for row in c.fetchall()}
    
    # Create sample comments
    comments = [
        ('Welcome to the Enhanced Blog', 'Alice Johnson', 'Great to see all these security features!'),
        ('Welcome to the Enhanced Blog', 'Bob Wilson', 'Looking forward to testing OAuth2.'),
        ('Understanding Web Security', 'Charlie Brown', 'Werkzeug PBKDF2 is a solid choice for password hashing.'),
        ('OAuth2 Explained', 'Diana Prince', 'This is a great explanation of OAuth2 flow.'),
        ('Two-Factor Authentication Guide', 'Eve Adams', 'Just enabled 2FA, works perfectly!'),
        ('Testing Security Features', 'Frank Miller', 'Account got locked after 3 attempts - protection works!'),
    ]
    
    print("\nCreating sample comments...")
    for post_title, author_name, content in comments:
        if post_title in post_dict:
            c.execute('INSERT INTO comments (post_id, author_name, content) VALUES (?, ?, ?)',
                     (post_dict[post_title], author_name, content))
            print(f"Created comment by {author_name}")
    
    # Commit changes
    conn.commit()
    conn.close()
    
    print(f"\n Database populated successfully!")
    print(f"\n Sample login credentials:")
    print(f"   Username: admin       Password: admin123      (No 2FA)")
    print(f"   Username: john_doe    Password: password123   (No 2FA)")
    print(f"   Username: jane_smith  Password: mypassword    (2FA enabled)")
    print(f"\n Tips:")
    print(f"   - Try logging in with wrong password 3 times to test lockout")
    print(f"   - jane_smith requires 2FA code (secret shown above)")
    print(f"   - Test OAuth2 with: python test_oauth.py")
    print(f"\n Ready to run: python app.py")

if __name__ == '__main__':
    try:
        populate_database()
    except Exception as e:
        print(f"\n Error: {e}")
        print("\nMake sure you've initialized the database first:")
        print("  python init_db_enhanced.py")