from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import bcrypt
from datetime import datetime, timedelta
import os
import re
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-jwt-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})
jwt = JWTManager(app)
socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_ORIGINS,
    async_mode='threading',
    logger=False,
    engineio_logger=False
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Supabase Database Connection
SUPABASE_DB_URL = os.getenv('SUPABASE_DB_URL')
if not SUPABASE_DB_URL:
    raise ValueError("❌ SUPABASE_DB_URL not set!")

try:
    db_pool = psycopg2.pool.ThreadedConnectionPool(
        1, 20,
        SUPABASE_DB_URL,
        cursor_factory=RealDictCursor
    )
    print("✅ Supabase database pool created successfully")
except Exception as e:
    print(f"❌ Database connection failed: {e}")
    raise

def get_db():
    return db_pool.getconn()

def release_db(conn):
    db_pool.putconn(conn)

active_users = {}

# Input Validation
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

def sanitize_input(text, max_length=500):
    if not text:
        return ""
    text = str(text).strip()
    text = text.replace('<', '').replace('>', '')
    return text[:max_length]

def require_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        return f(*args, **kwargs)
    return decorated_function

# ==================== AUTH ROUTES ====================
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
@require_json
def register():
    conn = None
    try:
        data = request.json
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        full_name = sanitize_input(data.get('full_name', ''), 100)

        if not username or not email or not password:
            return jsonify({'error': 'Missing required fields'}), 400
        if not validate_username(username):
            return jsonify({'error': 'Invalid username'}), 400
        if not validate_email(email):
            return jsonify({'error': 'Invalid email'}), 400

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, full_name) VALUES (%s, %s, %s, %s) RETURNING id",
            (username, email, password_hash, full_name)
        )
        user_id = cursor.fetchone()['id']
        conn.commit()
        cursor.close()

        token = create_access_token(identity=str(user_id))
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user_id': user_id,
            'username': username
        }), 201

    except psycopg2.IntegrityError:
        if conn:
            conn.rollback()
        return jsonify({'error': 'Username or email already exists'}), 409
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        if conn:
            release_db(conn)

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per hour")
@require_json
def login():
    conn = None
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, password_hash, full_name, profile_picture, bio FROM users WHERE username = %s OR email = %s",
            (username, username)
        )
        user = cursor.fetchone()
        cursor.close()

        if not user:
            bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            return jsonify({'error': 'Invalid credentials'}), 401

        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401

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
    finally:
        if conn:
            release_db(conn)

# ==================== USER ROUTES ====================
@app.route('/api/users/search', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
def search_users():
    conn = None
    try:
        query = sanitize_input(request.args.get('q', ''), 50)
        current_user_id = int(get_jwt_identity())

        if len(query) < 2:
            return jsonify({'users': []}), 200

        conn = get_db()
        cursor = conn.cursor()
        search_term = f'%{query}%'
        cursor.execute("""
            SELECT id, username, full_name, profile_picture, bio, is_online, last_seen
            FROM users
            WHERE (username ILIKE %s OR full_name ILIKE %s)
              AND id != %s
            LIMIT 20
        """, (search_term, search_term, current_user_id))
        users = cursor.fetchall()
        cursor.close()

        return jsonify({'users': users}), 200

    except Exception as e:
        print(f"Search error: {e}")
        return jsonify({'error': 'Search failed'}), 500
    finally:
        if conn:
            release_db(conn)

@app.route('/api/users/profile/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    conn = None
    try:
        if user_id <= 0:
            return jsonify({'error': 'Invalid user ID'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, full_name, profile_picture, bio, is_online, last_seen, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        cursor.close()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'user': user}), 200

    except Exception as e:
        print(f"Profile error: {e}")
        return jsonify({'error': 'Failed to fetch profile'}), 500
    finally:
        if conn:
            release_db(conn)

# ==================== FRIEND REQUEST ROUTES ====================
@app.route('/api/friends/request/send', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
@require_json
def send_friend_request():
    conn = None
    try:
        current_user_id = int(get_jwt_identity())
        receiver_id = request.json.get('receiver_id')

        if not receiver_id or not isinstance(receiver_id, int) or receiver_id <= 0:
            return jsonify({'error': 'Invalid receiver ID'}), 400
        if current_user_id == receiver_id:
            return jsonify({'error': 'Cannot send request to yourself'}), 400

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM friendships WHERE user_id = %s AND friend_id = %s",
            (current_user_id, receiver_id)
        )
        if cursor.fetchone():
            cursor.close()
            return jsonify({'error': 'Already friends'}), 409

        cursor.execute(
            "SELECT id, status FROM friend_requests WHERE sender_id = %s AND receiver_id = %s",
            (current_user_id, receiver_id)
        )
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            return jsonify({'error': f'Request already {existing["status"]}'}), 409

        cursor.execute(
            "INSERT INTO friend_requests (sender_id, receiver_id) VALUES (%s, %s) RETURNING id",
            (current_user_id, receiver_id)
        )
        request_id = cursor.fetchone()['id']
        conn.commit()
        cursor.close()

        if receiver_id in active_users:
            socketio.emit('friend_request_received', {
                'request_id': request_id,
                'sender_id': current_user_id
            }, room=active_users[receiver_id])

        return jsonify({'message': 'Friend request sent', 'request_id': request_id}), 201

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Friend request error: {e}")
        return jsonify({'error': 'Failed to send request'}), 500
    finally:
        if conn:
            release_db(conn)

@app.route('/api/friends/request/respond', methods=['POST'])
@jwt_required()
@require_json
def respond_friend_request():
    conn = None
    try:
        current_user_id = int(get_jwt_identity())
        request_id = request.json.get('request_id')
        action = request.json.get('action')

        if not request_id or not isinstance(request_id, int) or request_id <= 0:
            return jsonify({'error': 'Invalid request ID'}), 400
        if action not in ['accept', 'reject']:
            return jsonify({'error': 'Action must be "accept" or "reject"'}), 400

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM friend_requests WHERE id = %s AND receiver_id = %s AND status = 'pending'",
            (request_id, current_user_id)
        )
        friend_request = cursor.fetchone()

        if not friend_request:
            cursor.close()
            return jsonify({'error': 'Request not found'}), 404

        sender_id = friend_request['sender_id']

        if action == 'accept':
            cursor.execute(
                "UPDATE friend_requests SET status = 'accepted' WHERE id = %s",
                (request_id,)
            )
            cursor.execute(
                "INSERT INTO friendships (user_id, friend_id) VALUES (%s, %s), (%s, %s)",
                (current_user_id, sender_id, sender_id, current_user_id)
            )
            conn.commit()

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
            conn.commit()
            message = 'Friend request rejected'

        cursor.close()
        return jsonify({'message': message}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Respond request error: {e}")
        return jsonify({'error': 'Failed to respond'}), 500
    finally:
        if conn:
            release_db(conn)

@app.route('/api/friends/requests/pending', methods=['GET'])
@jwt_required()
def get_pending_requests():
    conn = None
    try:
        current_user_id = int(get_jwt_identity())

        conn = get_db()
        cursor = conn.cursor()
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

        return jsonify({'requests': requests}), 200

    except Exception as e:
        print(f"Pending requests error: {e}")
        return jsonify({'error': 'Failed to fetch requests'}), 500
    finally:
        if conn:
            release_db(conn)

@app.route('/api/friends/list', methods=['GET'])
@jwt_required()
def get_friends_list():
    conn = None
    try:
        current_user_id = int(get_jwt_identity())

        conn = get_db()
        cursor = conn.cursor()
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

        return jsonify({'friends': friends}), 200

    except Exception as e:
        print(f"Friends list error: {e}")
        return jsonify({'error': 'Failed to fetch friends'}), 500
    finally:
        if conn:
            release_db(conn)

# ==================== MESSAGING ROUTES ====================
@app.route('/api/messages/history/<int:friend_id>', methods=['GET'])
@jwt_required()
def get_message_history(friend_id):
    conn = None
    try:
        current_user_id = int(get_jwt_identity())
        limit = min(int(request.args.get('limit', 50)), 100)

        if friend_id <= 0:
            return jsonify({'error': 'Invalid friend ID'}), 400

        conn = get_db()
        cursor = conn.cursor()

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
        messages.reverse()

        cursor.execute("""
            UPDATE messages
            SET is_read = TRUE, read_at = CURRENT_TIMESTAMP
            WHERE sender_id = %s AND receiver_id = %s AND is_read = FALSE
        """, (friend_id, current_user_id))

        conn.commit()
        cursor.close()

        return jsonify({'messages': messages}), 200

    except Exception as e:
        print(f"Message history error: {e}")
        return jsonify({'error': 'Failed to fetch messages'}), 500
    finally:
        if conn:
            release_db(conn)

@app.route('/api/messages/send', methods=['POST'])
@jwt_required()
@limiter.limit("60 per minute")
@require_json
def send_message_rest():
    conn = None
    try:
        current_user_id = int(get_jwt_identity())
        data = request.json

        receiver_id = data.get('receiver_id')
        message_text = sanitize_input(data.get('message_text', ''), 2000)
        message_type = data.get('message_type', 'text')

        if not receiver_id or not isinstance(receiver_id, int) or receiver_id <= 0:
            return jsonify({'error': 'Invalid receiver ID'}), 400
        if not message_text or len(message_text.strip()) == 0:
            return jsonify({'error': 'Message cannot be empty'}), 400
        if message_type not in ['text', 'image', 'video', 'audio', 'file']:
            return jsonify({'error': 'Invalid message type'}), 400

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM friendships WHERE user_id = %s AND friend_id = %s",
            (current_user_id, receiver_id)
        )
        if not cursor.fetchone():
            cursor.close()
            return jsonify({'error': 'Can only message friends'}), 403

        is_delivered = receiver_id in active_users

        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, message_text, message_type, is_delivered, delivered_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, created_at
        """, (current_user_id, receiver_id, message_text, message_type, is_delivered, datetime.now() if is_delivered else None))

        result = cursor.fetchone()
        message_id = result['id']
        created_at = result['created_at']

        conn.commit()
        cursor.close()

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

        if receiver_id in active_users:
            socketio.emit('receive_message', message_data, room=active_users[receiver_id])

        return jsonify({
            'message': 'Message sent successfully',
            'data': message_data
        }), 201

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Send message error: {e}")
        return jsonify({'error': 'Failed to send message'}), 500
    finally:
        if conn:
            release_db(conn)

# ==================== WEBSOCKET EVENTS ====================
@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('authenticate')
def handle_authenticate(data):
    conn = None
    try:
        user_id = data.get('user_id')

        if not user_id or not isinstance(user_id, int) or user_id <= 0:
            emit('error', {'message': 'Invalid user ID'})
            return

        active_users[user_id] = request.sid
        join_room(f'user_{user_id}')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_online = TRUE WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()

        emit('user_online', {'user_id': user_id}, broadcast=True)
        print(f'User {user_id} authenticated')

    except Exception as e:
        print(f'Auth error: {e}')
        emit('error', {'message': 'Authentication failed'})
    finally:
        if conn:
            release_db(conn)

@socketio.on('disconnect')
def handle_disconnect():
    conn = None
    try:
        user_id = None
        for uid, sid in list(active_users.items()):
            if sid == request.sid:
                user_id = uid
                break

        if user_id:
            del active_users[user_id]
            leave_room(f'user_{user_id}')

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_online = FALSE, last_seen = CURRENT_TIMESTAMP WHERE id = %s", (user_id,))
            conn.commit()
            cursor.close()

            emit('user_offline', {'user_id': user_id}, broadcast=True)
            print(f'User {user_id} disconnected')

    except Exception as e:
        print(f'Disconnect error: {e}')
    finally:
        if conn:
            release_db(conn)

# ==================== HEALTH CHECK ====================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'database': 'Supabase PostgreSQL',
        'active_users': len(active_users),
        'timestamp': datetime.now().isoformat()
    }), 200

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ==================== START SERVER ====================
if __name__ == '__main__':
    port = int(os.getenv('PORT', 10000))
    debug_mode = os.getenv('DEBUG', 'false').lower() == 'true'
    
    print(f"🚀 Starting server on port {port}")
    print(f"🔒 Debug mode: {debug_mode}")
    print(f"✅ Connected to Supabase PostgreSQL")
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug_mode,
        allow_unsafe_werkzeug=True
    )
