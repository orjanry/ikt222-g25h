from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os
from datetime import datetime
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Database initialization
def init_db():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  email TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create posts table
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  content TEXT NOT NULL,
                  author_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (author_id) REFERENCES users (id))''')
    
    # Create comments table
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  post_id INTEGER,
                  author_name TEXT NOT NULL,
                  content TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (post_id) REFERENCES posts (id))''')
    
    conn.commit()
    conn.close()

# Utility functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT p.*, u.username 
        FROM posts p 
        JOIN users u ON p.author_id = u.id 
        ORDER BY p.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        if not username or not password or not email:
            flash('All fields are required!')
            return render_template('register.html')
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                        (username, hash_password(password), email))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?',
                           (username, hash_password(password))).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        flash('Please log in to create a post.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if not title or not content:
            flash('Title and content are required!')
            return render_template('create_post.html')
        
        conn = get_db_connection()
        conn.execute('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
                    (title, content, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Post created successfully!')
        return redirect(url_for('index'))
    
    return render_template('create_post.html')

@app.route('/post/<int:post_id>')
def view_post(post_id):
    conn = get_db_connection()
    
    # Get post with author information
    post = conn.execute('''
        SELECT p.*, u.username 
        FROM posts p 
        JOIN users u ON p.author_id = u.id 
        WHERE p.id = ?
    ''', (post_id,)).fetchone()
    
    if not post:
        flash('Post not found!')
        return redirect(url_for('index'))
    
    # Get comments for this post
    comments = conn.execute('''
        SELECT * FROM comments 
        WHERE post_id = ? 
        ORDER BY created_at ASC
    ''', (post_id,)).fetchall()
    
    conn.close()
    return render_template('post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    author_name = request.form['author_name']
    content = request.form['content']
    
    if not author_name or not content:
        flash('Name and comment are required!')
        return redirect(url_for('view_post', post_id=post_id))
    
    conn = get_db_connection()
    conn.execute('INSERT INTO comments (post_id, author_name, content) VALUES (?, ?, ?)',
                (post_id, author_name, content))
    conn.commit()
    conn.close()
    
    flash('Comment added successfully!')
    return redirect(url_for('view_post', post_id=post_id))

# VULNERABLE ENDPOINT - This demonstrates XSS vulnerability
@app.route('/vulnerable_search')
def vulnerable_search():
    search_query = request.args.get('q', '')
    
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT p.*, u.username 
        FROM posts p 
        JOIN users u ON p.author_id = u.id 
        WHERE p.title LIKE ? OR p.content LIKE ?
        ORDER BY p.created_at DESC
    ''', (f'%{search_query}%', f'%{search_query}%')).fetchall()
    conn.close()
    
    # VULNERABILITY: Directly inserting user input without escaping
    return render_template('vulnerable_search.html', posts=posts, query=Markup(search_query))

# SECURE ENDPOINT - This shows proper XSS prevention
@app.route('/secure_search')
def secure_search():
    search_query = request.args.get('q', '')
    
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT p.*, u.username 
        FROM posts p 
        JOIN users u ON p.author_id = u.id 
        WHERE p.title LIKE ? OR p.content LIKE ?
        ORDER BY p.created_at DESC
    ''', (f'%{search_query}%', f'%{search_query}%')).fetchall()
    conn.close()
    
    # SECURE: Letting Jinja2 automatically escape the query
    return render_template('secure_search.html', posts=posts, query=search_query)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)