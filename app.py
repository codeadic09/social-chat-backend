from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import mysql.connector
from mysql.connector import pooling
import bcrypt
from datetime import datetime, timedelta
import os
import re
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

app = Flask(__name__)

# ==================== SECURITY CONFIGURATION ====================
# 🔒 CRITICAL: Strong secrets (must be set in environment variables)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

if not app.config['SECRET_KEY'] or not app.config['JWT_SECRET_KEY']:
    raise ValueError("❌ SECRET_KEY and JWT_SECRET_KEY must be set in environment variables!")

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)  # Reduced from 30 days
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size

# 🔒 Restrict CORS to your app only (NOT "*")
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'https://your-app-domain.com').split(',')
CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

jwt = JWTManager(app)

socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_ORIGINS,
    async_mode='threading',
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

# 🔒 Rate Limiting (prevent DDoS and brute force)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Database connection pool
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '3306')),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'social_chat_app'),
    'pool_name': 'mypool',
    'pool_size': 10,
    'pool_reset_session': True
}

connection_pool = pooling.MySQLConnectionPool(**db_config)

def get_db():
    return connection_pool.get_connection()

# Store active socket connections
active_users = {}  # {user_id: socket_id}

# ==================== INPUT VALIDATION ====================
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """Username: 3-20 chars, alphanumeric + underscore only"""
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

def validate_password(password):
    """Password: min 8 chars, must have uppercase, lowercase, digit"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain a digit"
    return True, "Valid"

def sanitize_input(text, max_length=500):
    """Remove dangerous characters and limit length"""
    if not text:
        return ""
    text = str(text).strip()
    # Remove potential XSS characters
    text = text.replace('<', '').replace('>', '').replace('"', '').replace("'", '')
    return text[:max_length]

# ==================== SECURITY DECORATORS ====================
def require_json(f):
    """Ensure request has JSON content type"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        return f(*args, **kwargs)
    return decorated_function

# ==================== AUTH ROUTES ====================
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per hour")  # Prevent spam registration
@require_json
def register():
    try:
        data = request.json
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        full_name = sanitize_input(data.get('full_name', ''), max_length=100)

        # 🔒 Validate inputs
        if not username or not email or not password:
            return jsonify({'error': 'Missing required fields'}), 400

        if not validate_username(username):
            return jsonify({'error': 'Username must be 3-20 characters, alphanumeric only'}), 400

        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        is_valid, msg = validate_password(password)
        if not is_valid:
            return jsonify({'error': msg}), 400

        # Hash password with strong work factor
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

        db = get_db()
        cursor = db.cursor()
        
        # 🔒 Use parameterized query (prevents SQL injection)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, full_name) VALUES (%s, %s, %s, %s)",
            (username, email, password_hash, full_name)
        )
        
        db.commit()
        user_id = cursor.lastrowid
        cursor.close()
        db.close()

        # Create JWT token
        token = create_access_token(identity=str(user_id))

        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user_id': user_id,
            'username': username
        }), 201

    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Username or email already exists'}), 409
    except Exception as e:
        print(f"Registration error: {e}")  # Log but don't expose
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per hour")  # Prevent brute force
@require_json
def login():
    try:
        data = request.json
        
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        # 🔒 Parameterized query
        cursor.execute(
            "SELECT id, username, email, password_hash, full_name, profile_picture, bio FROM users WHERE username = %s OR email = %s",
            (username, username)
        )
        
        user = cursor.fetchone()
        cursor.close()
        db.close()

        # 🔒 Constant-time comparison to prevent timing attacks
        if not user:
            # Still hash to prevent timing attack
            bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            return jsonify({'error': 'Invalid credentials'}), 401

        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Create JWT token
        token = create_access_token(identity=str(user['id']))

        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'full_name': user['full_name'],
                'profile_picture': user['profile_picture'],
                'bio': user['bio']
            }
        }), 200

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

# ==================== USER ROUTES ====================
@app.route('/api/users/search', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
def search_users():
    try:
        query = sanitize_input(request.args.get('q', ''), max_length=50)
        current_user_id = int(get_jwt_identity())

        if len(query) < 2:
            return jsonify({'users': []}), 200

        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        # 🔒 Parameterized query with LIMIT
        search_term = f'%{query}%'
        cursor.execute("""
            SELECT id, username, full_name, profile_picture, bio, is_online, last_seen
            FROM users
            WHERE (username LIKE %s OR full_name LIKE %s)
            AND id != %s
            LIMIT 20
        """, (search_term, search_term, current_user_id))
        
        users = cursor.fetchall()
        cursor.close()
        db.close()

        return jsonify({'users': users}), 200

    except Exception as e:
        print(f"Search error: {e}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/users/profile/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    try:
        # 🔒 Validate user_id is positive integer
        if user_id <= 0:
            return jsonify({'error': 'Invalid user ID'}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute(
            "SELECT id, username, full_name, profile_picture, bio, is_online, last_seen, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'user': user}), 200

    except Exception as e:
        print(f"Profile error: {e}")
        return jsonify({'error': 'Failed to fetch profile'}), 500

# ==================== FRIEND REQUEST ROUTES ====================
@app.route('/api/friends/request/send', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")  # Prevent spam
@require_json
def send_friend_request():
    try:
        current_user_id = int(get_jwt_identity())
        receiver_id = request.json.get('receiver_id')

        # 🔒 Validate input
        if not receiver_id or not isinstance(receiver_id, int) or receiver_id <= 0:
            return jsonify({'error': 'Invalid receiver ID'}), 400

        if current_user_id == receiver_id:
            return jsonify({'error': 'Cannot send request to yourself'}), 400

        db = get_db()
        cursor = db.cursor()

        # Check if already friends
        cursor.execute(
            "SELECT id FROM friendships WHERE user_id = %s AND friend_id = %s",
            (current_user_id, receiver_id)
        )
        
        if cursor.fetchone():
            cursor.close()
            db.close()
            return jsonify({'error': 'Already friends'}), 409

        # Check if request already exists
        cursor.execute(
            "SELECT id, status FROM friend_requests WHERE sender_id = %s AND receiver_id = %s",
            (current_user_id, receiver_id)
        )
        
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            db.close()
            return jsonify({'error': f'Request already {existing[1]}'}), 409

        # Create friend request
        cursor.execute(
            "INSERT INTO friend_requests (sender_id, receiver_id) VALUES (%s, %s)",
            (current_user_id, receiver_id)
        )
        
        db.commit()
        request_id = cursor.lastrowid
        cursor.close()
        db.close()

        # Emit real-time notification
        if receiver_id in active_users:
            socketio.emit('friend_request_received', {
                'request_id': request_id,
                'sender_id': current_user_id
            }, room=active_users[receiver_id])

        return jsonify({'message': 'Friend request sent', 'request_id': request_id}), 201

    except Exception as e:
        print(f"Friend request error: {e}")
        return jsonify({'error': 'Failed to send request'}), 500

@app.route('/api/friends/request/respond', methods=['POST'])
@jwt_required()
@require_json
def respond_friend_request():
    try:
        current_user_id = int(get_jwt_identity())
        request_id = request.json.get('request_id')
        action = request.json.get('action')

        # 🔒 Validate inputs
        if not request_id or not isinstance(request_id, int) or request_id <= 0:
            return jsonify({'error': 'Invalid request ID'}), 400

        if action not in ['accept', 'reject']:
            return jsonify({'error': 'Action must be "accept" or "reject"'}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Verify request exists and belongs to current user
        cursor.execute(
            "SELECT * FROM friend_requests WHERE id = %s AND receiver_id = %s AND status = 'pending'",
            (request_id, current_user_id)
        )
        
        friend_request = cursor.fetchone()

        if not friend_request:
            cursor.close()
            db.close()
            return jsonify({'error': 'Request not found'}), 404

        sender_id = friend_request['sender_id']

        if action == 'accept':
            # Update request status
            cursor.execute(
                "UPDATE friend_requests SET status = 'accepted' WHERE id = %s",
                (request_id,)
            )
            
            # Create bidirectional friendship
            cursor.execute(
                "INSERT INTO friendships (user_id, friend_id) VALUES (%s, %s), (%s, %s)",
                (current_user_id, sender_id, sender_id, current_user_id)
            )
            
            db.commit()

            # Notify sender
            if sender_id in active_users:
                socketio.emit('friend_request_accepted', {
                    'user_id': current_user_id
                }, room=active_users[sender_id])

            message = 'Friend request accepted'
        else:
            cursor.execute(
                "UPDATE friend_requests SET status = 'rejected' WHERE id = %s",
                (request_id,)
            )
            db.commit()
            message = 'Friend request rejected'

        cursor.close()
        db.close()

        return jsonify({'message': message}), 200

    except Exception as e:
        print(f"Respond request error: {e}")
        return jsonify({'error': 'Failed to respond'}), 500

@app.route('/api/friends/requests/pending', methods=['GET'])
@jwt_required()
def get_pending_requests():
    try:
        current_user_id = int(get_jwt_identity())

        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT fr.id, fr.sender_id, fr.created_at,
                   u.username, u.full_name, u.profile_picture
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = %s AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
            LIMIT 50
        """, (current_user_id,))
        
        requests = cursor.fetchall()
        cursor.close()
        db.close()

        return jsonify({'requests': requests}), 200

    except Exception as e:
        print(f"Pending requests error: {e}")
        return jsonify({'error': 'Failed to fetch requests'}), 500

@app.route('/api/friends/list', methods=['GET'])
@jwt_required()
def get_friends_list():
    try:
        current_user_id = int(get_jwt_identity())

        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT u.id, u.username, u.full_name, u.profile_picture, u.bio,
                   u.is_online, u.last_seen
            FROM friendships f
            JOIN users u ON f.friend_id = u.id
            WHERE f.user_id = %s
            ORDER BY u.is_online DESC, u.username ASC
            LIMIT 100
        """, (current_user_id,))
        
        friends = cursor.fetchall()
        cursor.close()
        db.close()

        return jsonify({'friends': friends}), 200

    except Exception as e:
        print(f"Friends list error: {e}")
        return jsonify({'error': 'Failed to fetch friends'}), 500

# ==================== MESSAGING ROUTES ====================
@app.route('/api/messages/history/<int:friend_id>', methods=['GET'])
@jwt_required()
def get_message_history(friend_id):
    try:
        current_user_id = int(get_jwt_identity())
        limit = min(int(request.args.get('limit', 50)), 100)  # 🔒 Cap at 100

        # 🔒 Validate friend_id
        if friend_id <= 0:
            return jsonify({'error': 'Invalid friend ID'}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, sender_id, receiver_id, message_text, message_type,
                   media_url, is_read, is_delivered, created_at
            FROM messages
            WHERE (sender_id = %s AND receiver_id = %s)
               OR (sender_id = %s AND receiver_id = %s)
            ORDER BY created_at DESC
            LIMIT %s
        """, (current_user_id, friend_id, friend_id, current_user_id, limit))
        
        messages = cursor.fetchall()
        messages.reverse()  # Oldest first

        # Mark messages as read
        cursor.execute("""
            UPDATE messages
            SET is_read = TRUE, read_at = NOW()
            WHERE sender_id = %s AND receiver_id = %s AND is_read = FALSE
        """, (friend_id, current_user_id))
        
        db.commit()
        cursor.close()
        db.close()

        return jsonify({'messages': messages}), 200

    except Exception as e:
        print(f"Message history error: {e}")
        return jsonify({'error': 'Failed to fetch messages'}), 500

@app.route('/api/messages/send', methods=['POST'])
@jwt_required()
@limiter.limit("60 per minute")  # Prevent spam
@require_json
def send_message_rest():
    try:
        current_user_id = int(get_jwt_identity())
        data = request.json
        
        receiver_id = data.get('receiver_id')
        message_text = sanitize_input(data.get('message_text', ''), max_length=2000)
        message_type = data.get('message_type', 'text')

        # 🔒 Validate inputs
        if not receiver_id or not isinstance(receiver_id, int) or receiver_id <= 0:
            return jsonify({'error': 'Invalid receiver ID'}), 400

        if not message_text or len(message_text.strip()) == 0:
            return jsonify({'error': 'Message cannot be empty'}), 400

        if message_type not in ['text', 'image', 'video', 'audio', 'file']:
            return jsonify({'error': 'Invalid message type'}), 400

        # Check if users are friends
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute(
            "SELECT id FROM friendships WHERE user_id = %s AND friend_id = %s",
            (current_user_id, receiver_id)
        )
        
        if not cursor.fetchone():
            cursor.close()
            db.close()
            return jsonify({'error': 'Can only message friends'}), 403

        # Check if receiver is online
        is_delivered = receiver_id in active_users

        # Save message
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, message_text, message_type, is_delivered, delivered_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (current_user_id, receiver_id, message_text, message_type, is_delivered, datetime.now() if is_delivered else None))
        
        db.commit()
        message_id = cursor.lastrowid
        
        cursor.execute("SELECT created_at FROM messages WHERE id = %s", (message_id,))
        created_at = cursor.fetchone()[0]
        
        cursor.close()
        db.close()

        message_data = {
            'id': message_id,
            'sender_id': current_user_id,
            'receiver_id': receiver_id,
            'message_text': message_text,
            'message_type': message_type,
            'is_delivered': is_delivered,
            'is_read': False,
            'created_at': created_at.isoformat()
        }

        # Send via WebSocket if online
        if receiver_id in active_users:
            socketio.emit('receive_message', message_data, room=active_users[receiver_id])

        return jsonify({
            'message': 'Message sent successfully',
            'data': message_data
        }), 201

    except Exception as e:
        print(f"Send message error: {e}")
        return jsonify({'error': 'Failed to send message'}), 500

# ==================== WEBSOCKET EVENTS ====================
@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('authenticate')
def handle_authenticate(data):
    try:
        user_id = data.get('user_id')
        
        # 🔒 Validate user_id
        if not user_id or not isinstance(user_id, int) or user_id <= 0:
            emit('error', {'message': 'Invalid user ID'})
            return

        active_users[user_id] = request.sid
        join_room(f'user_{user_id}')

        # Update online status
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET is_online = TRUE WHERE id = %s", (user_id,))
        db.commit()
        cursor.close()
        db.close()

        # Notify friends
        emit('user_online', {'user_id': user_id}, broadcast=True)
        print(f'User {user_id} authenticated')

    except Exception as e:
        print(f'Auth error: {e}')
        emit('error', {'message': 'Authentication failed'})

@socketio.on('disconnect')
def handle_disconnect():
    try:
        # Find and remove user
        user_id = None
        for uid, sid in list(active_users.items()):
            if sid == request.sid:
                user_id = uid
                break

        if user_id:
            del active_users[user_id]
            leave_room(f'user_{user_id}')

            # Update offline status
            db = get_db()
            cursor = db.cursor()
            cursor.execute("UPDATE users SET is_online = FALSE, last_seen = NOW() WHERE id = %s", (user_id,))
            db.commit()
            cursor.close()
            db.close()

            # Notify friends
            emit('user_offline', {'user_id': user_id}, broadcast=True)
            print(f'User {user_id} disconnected')

    except Exception as e:
        print(f'Disconnect error: {e}')

@socketio.on('send_message')
def handle_send_message(data):
    try:
        sender_id = data.get('sender_id')
        receiver_id = data.get('receiver_id')
        message_text = sanitize_input(data.get('message_text', ''), max_length=2000)
        message_type = data.get('message_type', 'text')

        # 🔒 Validate inputs
        if not all([sender_id, receiver_id, message_text]):
            emit('error', {'message': 'Missing data'})
            return

        if not isinstance(sender_id, int) or not isinstance(receiver_id, int):
            emit('error', {'message': 'Invalid user IDs'})
            return

        # Save to database
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, message_text, message_type, is_delivered)
            VALUES (%s, %s, %s, %s, %s)
        """, (sender_id, receiver_id, message_text, message_type, receiver_id in active_users))
        
        db.commit()
        message_id = cursor.lastrowid
        
        cursor.execute("SELECT created_at FROM messages WHERE id = %s", (message_id,))
        created_at = cursor.fetchone()[0]
        
        cursor.close()
        db.close()

        message_data = {
            'id': message_id,
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message_text': message_text,
            'message_type': message_type,
            'is_delivered': receiver_id in active_users,
            'is_read': False,
            'created_at': created_at.isoformat()
        }

        # Send to receiver if online
        if receiver_id in active_users:
            socketio.emit('receive_message', message_data, room=active_users[receiver_id])

            # Update delivery status
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "UPDATE messages SET is_delivered = TRUE, delivered_at = NOW() WHERE id = %s",
                (message_id,)
            )
            db.commit()
            cursor.close()
            db.close()

        # Confirm to sender
        emit('message_sent', message_data)

    except Exception as e:
        emit('error', {'message': 'Failed to send message'})
        print(f'Message error: {e}')

@socketio.on('typing')
def handle_typing(data):
    try:
        receiver_id = data.get('receiver_id')
        sender_id = data.get('sender_id')
        is_typing = data.get('is_typing', True)

        # 🔒 Validate inputs
        if not isinstance(receiver_id, int) or not isinstance(sender_id, int):
            return

        if receiver_id in active_users:
            socketio.emit('user_typing', {
                'user_id': sender_id,
                'is_typing': is_typing
            }, room=active_users[receiver_id])

    except Exception as e:
        print(f'Typing error: {e}')

# ==================== HEALTH CHECK ====================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_users': len(active_users)
    }), 200

# 🔒 Remove all debug endpoints in production
# Only enable if DEBUG mode is explicitly set
if os.getenv('DEBUG') == 'true':
    @app.route('/api/debug/users', methods=['GET'])
    def debug_users():
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            cursor.execute("SELECT id, username, email, is_online FROM users LIMIT 10")
            users = cursor.fetchall()
            cursor.close()
            db.close()
            return jsonify({'users': users}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ==================== START SERVER ====================
if __name__ == '__main__':
    port = int(os.getenv('PORT', 10000))
    
    # 🔒 NEVER use debug=True in production
    debug_mode = os.getenv('DEBUG', 'false').lower() == 'true'
    
    print(f"🚀 Starting server on port {port}")
    print(f"🔒 Debug mode: {debug_mode}")
    print(f"🔒 Active CORS origins: {ALLOWED_ORIGINS}")
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug_mode,
        allow_unsafe_werkzeug=True
    )
