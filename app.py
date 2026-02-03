from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import mysql.connector
from mysql.connector import pooling
import bcrypt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

CORS(app, resources={r"/*": {"origins": "*"}})
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')


# Database connection pool
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '3306')),  # Make sure this line exists
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'social_chat_app'),
    'pool_name': 'mypool',
    'pool_size': 10
}


connection_pool = pooling.MySQLConnectionPool(**db_config)

def get_db():
    return connection_pool.get_connection()

# Store active socket connections
active_users = {}  # {user_id: socket_id}

# ==================== AUTH ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        full_name = data.get('full_name', '')
        
        if not username or not email or not password:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        db = get_db()
        cursor = db.cursor()
        
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
        
    except mysql.connector.IntegrityError as e:
        return jsonify({'error': 'Username or email already exists'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400
        
        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute(
            "SELECT id, username, email, password_hash, full_name, profile_picture, bio FROM users WHERE username = %s OR email = %s",
            (username, username)
        )
        user = cursor.fetchone()
        
        cursor.close()
        db.close()
        
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
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
        return jsonify({'error': str(e)}), 500

# ==================== USER ROUTES ====================

@app.route('/api/users/search', methods=['GET'])
@jwt_required()
def search_users():
    try:
        query = request.args.get('q', '')
        current_user_id = int(get_jwt_identity())
        
        if len(query) < 2:
            return jsonify({'users': []}), 200
        
        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, username, full_name, profile_picture, bio, is_online, last_seen 
            FROM users 
            WHERE (username LIKE %s OR full_name LIKE %s OR email LIKE %s) 
            AND id != %s 
            LIMIT 20
        """, (f'%{query}%', f'%{query}%', f'%{query}%', current_user_id))
        
        users = cursor.fetchall()
        
        cursor.close()
        db.close()
        
        return jsonify({'users': users}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/profile/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute(
            "SELECT id, username, full_name, profile_picture, bio, is_online, last_seen, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        cursor.close()
        db.close()
        
        return jsonify({'user': user}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== FRIEND REQUEST ROUTES ====================

@app.route('/api/friends/request/send', methods=['POST'])
@jwt_required()
def send_friend_request():
    try:
        current_user_id = int(get_jwt_identity())
        receiver_id = request.json.get('receiver_id')
        
        if not receiver_id:
            return jsonify({'error': 'Receiver ID required'}), 400
        
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
            return jsonify({'error': 'Already friends'}), 409
        
        # Check if request already exists
        cursor.execute(
            "SELECT id, status FROM friend_requests WHERE sender_id = %s AND receiver_id = %s",
            (current_user_id, receiver_id)
        )
        existing = cursor.fetchone()
        
        if existing:
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
        
        # Emit real-time notification to receiver
        if receiver_id in active_users:
            socketio.emit('friend_request_received', {
                'request_id': request_id,
                'sender_id': current_user_id
            }, room=active_users[receiver_id])
        
        return jsonify({'message': 'Friend request sent', 'request_id': request_id}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/friends/request/respond', methods=['POST'])
@jwt_required()
def respond_friend_request():
    try:
        current_user_id = get_jwt_identity()
        request_id = request.json.get('request_id')
        action = request.json.get('action')  # 'accept' or 'reject'
        
        if not request_id or action not in ['accept', 'reject']:
            return jsonify({'error': 'Invalid request'}), 400
        
        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        # Verify request exists and is for current user
        cursor.execute(
            "SELECT * FROM friend_requests WHERE id = %s AND receiver_id = %s AND status = 'pending'",
            (request_id, current_user_id)
        )
        friend_request = cursor.fetchone()
        
        if not friend_request:
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/friends/requests/pending', methods=['GET'])
@jwt_required()
def get_pending_requests():
    try:
        current_user_id = get_jwt_identity()
        
        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT fr.id, fr.sender_id, fr.created_at, 
                   u.username, u.full_name, u.profile_picture
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = %s AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
        """, (current_user_id,))
        
        requests = cursor.fetchall()
        
        cursor.close()
        db.close()
        
        return jsonify({'requests': requests}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/friends/list', methods=['GET'])
@jwt_required()
def get_friends_list():
    try:
        current_user_id = get_jwt_identity()
        
        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT u.id, u.username, u.full_name, u.profile_picture, u.bio, 
                   u.is_online, u.last_seen
            FROM friendships f
            JOIN users u ON f.friend_id = u.id
            WHERE f.user_id = %s
            ORDER BY u.is_online DESC, u.username ASC
        """, (current_user_id,))
        
        friends = cursor.fetchall()
        
        cursor.close()
        db.close()
        
        return jsonify({'friends': friends}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== MESSAGING ROUTES ====================

@app.route('/api/messages/history/<int:friend_id>', methods=['GET'])
@jwt_required()
def get_message_history(friend_id):
    try:
        current_user_id = get_jwt_identity()
        limit = request.args.get('limit', 50, type=int)
        
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
        return jsonify({'error': str(e)}), 500
    

# ==================== REST MESSAGE SENDING (for testing) ====================

@app.route('/api/messages/send', methods=['POST'])
@jwt_required()
def send_message_rest():
    try:
        current_user_id = int(get_jwt_identity())
        data = request.json
        receiver_id = data.get('receiver_id')
        message_text = data.get('message_text')
        message_type = data.get('message_type', 'text')
        media_url = data.get('media_url')
        
        if not receiver_id or not message_text:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check if users are friends
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute(
            "SELECT id FROM friendships WHERE user_id = %s AND friend_id = %s",
            (current_user_id, receiver_id)
        )
        if not cursor.fetchone():
            return jsonify({'error': 'Can only message friends'}), 403
        
        # Check if receiver is online
        is_delivered = receiver_id in active_users
        
        # Save message
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, message_text, message_type, media_url, is_delivered, delivered_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (current_user_id, receiver_id, message_text, message_type, media_url, is_delivered, datetime.now() if is_delivered else None))
        
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
            'media_url': media_url,
            'is_delivered': is_delivered,
            'is_read': False,
            'created_at': created_at.isoformat()
        }
        
        # If receiver is online, send via WebSocket too
        if receiver_id in active_users:
            socketio.emit('receive_message', message_data, room=active_users[receiver_id])
        
        return jsonify({
            'message': 'Message sent successfully',
            'data': message_data
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== WEBSOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('authenticate')
def handle_authenticate(data):
    try:
        user_id = data.get('user_id')
        if user_id:
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

@socketio.on('disconnect')
def handle_disconnect():
    try:
        # Find and remove user
        user_id = None
        for uid, sid in active_users.items():
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
        message_text = data.get('message_text')
        message_type = data.get('message_type', 'text')
        
        if not all([sender_id, receiver_id, message_text]):
            emit('error', {'message': 'Missing data'})
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
        emit('error', {'message': str(e)})
        print(f'Message error: {e}')

@socketio.on('typing')
def handle_typing(data):
    receiver_id = data.get('receiver_id')
    sender_id = data.get('sender_id')
    is_typing = data.get('is_typing', True)
    
    if receiver_id in active_users:
        socketio.emit('user_typing', {
            'user_id': sender_id,
            'is_typing': is_typing
        }, room=active_users[receiver_id])

# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200

if __name__ == '__main__':
    # Local development only
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
else:
    # Production (Render will use gunicorn)
    pass
