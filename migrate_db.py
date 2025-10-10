#!/usr/bin/env python3
"""
Database Migration Script
Migrates from Assignment 1 database schema to Assignment 2 enhanced schema
Preserves existing users and posts while adding new authentication features
"""

import sqlite3
import shutil
from datetime import datetime
from werkzeug.security import generate_password_hash

def backup_database():
    """Create a backup of the existing database"""
    try:
        shutil.copy2('blog.db', f'blog_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
        print("Database backup created")
        return True
    except FileNotFoundError:
        print("!No existing database found - will create new one")
        return False
    except Exception as e:
        print(f"Backup failed: {e}")
        return False

def migrate_database():
    """Migrate database schema from Assignment 1 to Assignment 2"""
    
    print("=" * 60)
    print("Database Migration: Assignment 1 → Assignment 2")
    print("=" * 60)
    
    # Create backup first
    has_existing_db = backup_database()
    
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    if has_existing_db:
        print("\n[Step 1] Checking existing schema...")
        
        # Check if old users table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        users_exists = c.fetchone() is not None
        
        if users_exists:
            print("Found existing users table")
            
            # Check current schema
            c.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in c.fetchall()]
            
            print(f"  Current columns: {', '.join(columns)}")
            
            # Check if we need to add new columns
            new_columns_needed = [
                ('totp_secret', 'TEXT'),
                ('totp_enabled', 'INTEGER DEFAULT 0'),
                ('oauth_provider', 'TEXT'),
                ('oauth_id', 'TEXT'),
                ('account_locked', 'INTEGER DEFAULT 0'),
                ('lock_until', 'TIMESTAMP'),
                ('last_login', 'TIMESTAMP')
            ]
            
            for col_name, col_type in new_columns_needed:
                if col_name not in columns:
                    print(f"  Adding column: {col_name}")
                    try:
                        c.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                    except sqlite3.OperationalError as e:
                        print(f"  ! Column {col_name} might already exist: {e}")
            
            # Migrate passwords from SHA256 to Werkzeug PBKDF2
            print("\n[Step 2] Migrating password hashes to Werkzeug PBKDF2...")
            print("  ! Note: This will reset all user passwords to 'password123'")
            print("  ! Users will need to reset their passwords")
            
            response = input("  Continue with password migration? (yes/no): ")
            if response.lower() == 'yes':
                c.execute("SELECT id, username FROM users")
                users = c.fetchall()
                
                for user_id, username in users:
                    # Set default password (users will need to reset)
                    default_password = "password123"
                    hashed = generate_password_hash(default_password, method='pbkdf2:sha256', salt_length=16)
                    
                    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed, user_id))
                    print(f"Migrated password for user: {username}")
                
                print("Password migration complete")
                print("All users should use password 'password123' initially")
    else:
        print("\n[Step 1] No existing database - creating fresh schema...")
    
    # Create new tables
    print("\n[Step 3] Creating new authentication tables...")
    
    # Login attempts table
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  ip_address TEXT,
                  success INTEGER DEFAULT 0,
                  attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    print("Created login_attempts table")
    
    # OAuth authorization codes
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_auth_codes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  code TEXT UNIQUE NOT NULL,
                  client_id TEXT NOT NULL,
                  user_id INTEGER,
                  redirect_uri TEXT NOT NULL,
                  scope TEXT,
                  expires_at TIMESTAMP NOT NULL,
                  used INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    print("Created oauth_auth_codes table")
    
    # OAuth access tokens
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  access_token TEXT UNIQUE NOT NULL,
                  refresh_token TEXT UNIQUE,
                  client_id TEXT NOT NULL,
                  user_id INTEGER,
                  scope TEXT,
                  expires_at TIMESTAMP NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    print("Created oauth_tokens table")
    
    # OAuth registered clients
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_clients
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  client_id TEXT UNIQUE NOT NULL,
                  client_secret TEXT NOT NULL,
                  client_name TEXT NOT NULL,
                  redirect_uris TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    print("Created oauth_clients table")
    
    # Insert default OAuth client for testing
    print("\n[Step 4] Setting up default OAuth client...")
    
    try:
        c.execute('''INSERT INTO oauth_clients 
                     (client_id, client_secret, client_name, redirect_uris) 
                     VALUES (?, ?, ?, ?)''',
                  ('test_client_123', 
                   'test_secret_456', 
                   'Test OAuth Client',
                   'http://localhost:5000/callback,http://localhost:3000/callback'))
        print("    Default OAuth client created")
        print("    Client ID: test_client_123")
        print("    Client Secret: test_secret_456")
    except sqlite3.IntegrityError:
        print("!OAuth client already exists")
    
    # Ensure posts and comments tables exist
    print("\n[Step 5] Ensuring blog tables exist...")
    
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  content TEXT NOT NULL,
                  author_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (author_id) REFERENCES users (id))''')
    print("Posts table ready")
    
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  post_id INTEGER,
                  author_name TEXT NOT NULL,
                  content TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (post_id) REFERENCES posts (id))''')
    print("Comments table ready")
    
    # Create indexes for performance
    print("\n[Step 6] Creating indexes for performance...")
    
    try:
        c.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempt_time)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_oauth_codes_code ON oauth_auth_codes(code)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_oauth_tokens_token ON oauth_tokens(access_token)')
        print("Indexes created")
    except sqlite3.OperationalError as e:
        print(f"!Some indexes may already exist: {e}")
    
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 60)
    print("Migration Complete!")
    print("=" * 60)
    
    print("\nDatabase Summary:")
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # Count records
    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM posts")
    post_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM oauth_clients")
    client_count = c.fetchone()[0]
    
    print(f"  Users: {user_count}")
    print(f"  Posts: {post_count}")
    print(f"  OAuth Clients: {client_count}")
    
    conn.close()
    

def create_fresh_database():
    """Create a completely fresh database with Assignment 2 schema"""
    print("\nCreating fresh database for Assignment 2...")
    
    from init_db_enhanced import init_enhanced_db
    init_enhanced_db()
    
    print("Fresh database created successfully!")

if __name__ == '__main__':
    import os
    
    print("\nDatabase Migration Tool")
    print("-" * 60)
    
    if os.path.exists('blog.db'):
        print("Existing database found: blog.db")
        print("\nOptions:")
        print("1. Migrate existing database (preserves data, resets passwords)")
        print("2. Create fresh database (deletes all existing data)")
        print("3. Cancel")
        
        choice = input("\nSelect option (1-3): ")
        
        if choice == '1':
            migrate_database()
        elif choice == '2':
            confirm = input("This will DELETE all existing data. Are you sure? (yes/no): ")
            if confirm.lower() == 'yes':
                # Backup first
                backup_database()
                # Delete old database
                os.remove('blog.db')
                # Create fresh
                create_fresh_database()
            else:
                print("Cancelled.")
        else:
            print("Cancelled.")
    else:
        print("No existing database found.")
        create_fresh_database()
    
    # OAuth authorization codes
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_auth_codes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  code TEXT UNIQUE NOT NULL,
                  client_id TEXT NOT NULL,
                  user_id INTEGER,
                  redirect_uri TEXT NOT NULL,
                  scope TEXT,
                  expires_at TIMESTAMP NOT NULL,
                  used INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    print("Created oauth_auth_codes table")
    
    # OAuth access tokens
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  access_token TEXT UNIQUE NOT NULL,
                  refresh_token TEXT UNIQUE,
                  client_id TEXT NOT NULL,
                  user_id INTEGER,
                  scope TEXT,
                  expires_at TIMESTAMP NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    print("Created oauth_tokens table")
    
    # OAuth registered clients
    c.execute('''CREATE TABLE IF NOT EXISTS oauth_clients
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  client_id TEXT UNIQUE NOT NULL,
                  client_secret TEXT NOT NULL,
                  client_name TEXT NOT NULL,
                  redirect_uris TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    print("Created oauth_clients table")
    
    # Insert default OAuth client for testing
    print("\n[Step 4] Setting up default OAuth client...")
    
    try:
        c.execute('''INSERT INTO oauth_clients 
                     (client_id, client_secret, client_name, redirect_uris) 
                     VALUES (?, ?, ?, ?)''',
                  ('test_client_123', 
                   'test_secret_456', 
                   'Test OAuth Client',
                   'http://localhost:5000/callback,http://localhost:3000/callback'))
        print("    Default OAuth client created")
        print("    Client ID: test_client_123")
        print("    Client Secret: test_secret_456")
    except sqlite3.IntegrityError:
        print("!OAuth client already exists")
    
    # Ensure posts and comments tables exist
    print("\n[Step 5] Ensuring blog tables exist...")
    
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  content TEXT NOT NULL,
                  author_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (author_id) REFERENCES users (id))''')
    print("Posts table ready")
    
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  post_id INTEGER,
                  author_name TEXT NOT NULL,
                  content TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (post_id) REFERENCES posts (id))''')
    print("Comments table ready")
    
    # Create indexes for performance
    print("\n[Step 6] Creating indexes for performance...")
    
    try:
        c.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempt_time)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_oauth_codes_code ON oauth_auth_codes(code)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_oauth_tokens_token ON oauth_tokens(access_token)')
        print("Indexes created")
    except sqlite3.OperationalError as e:
        print(f"  ! Some indexes may already exist: {e}")
    
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 60)
    print("Migration Complete!")
    print("=" * 60)
    
    print("\nDatabase Summary:")
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # Count records
    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM posts")
    post_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM oauth_clients")
    client_count = c.fetchone()[0]
    
    print(f"  Users: {user_count}")
    print(f"  Posts: {post_count}")
    print(f"  OAuth Clients: {client_count}")
    
    conn.close()
    

def create_fresh_database():
    """Create a completely fresh database with Assignment 2 schema"""
    print("\nCreating fresh database for Assignment 2...")
    
    from init_db_enhanced import init_enhanced_db
    init_enhanced_db()
    
    print("Fresh database created successfully!")

if __name__ == '__main__':
    import os
    
    print("\nDatabase Migration Tool")
    print("-" * 60)
    
    if os.path.exists('blog.db'):
        print("Existing database found: blog.db")
        print("\nOptions:")
        print("1. Migrate existing database (preserves data, resets passwords)")
        print("2. Create fresh database (deletes all existing data)")
        print("3. Cancel")
        
        choice = input("\nSelect option (1-3): ")
        
        if choice == '1':
            migrate_database()
        elif choice == '2':
            confirm = input("This will DELETE all existing data. Are you sure? (yes/no): ")
            if confirm.lower() == 'yes':
                # Backup first
                backup_database()
                # Delete old database
                os.remove('blog.db')
                # Create fresh
                create_fresh_database()
            else:
                print("Cancelled.")
        else:
            print("Cancelled.")
    else:
        print("No existing database found.")
        create_fresh_database()