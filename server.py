import jwt
from flask import Flask, request, jsonify, g
from functools import wraps
import datetime
import logging
import uuid
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("zt_access.log"), logging.StreamHandler()]
)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = "very-secure-secret-key"  

# ----- ZERO TRUST COMPONENTS -----

users_db = {
    'alice': {
        'password': generate_password_hash('alice_password'),
        'role': 'admin',
        'device_id': 'device_001'
    },
    'bob': {
        'password': generate_password_hash('bob_password'),
        'role': 'user',
        'device_id': 'device_002'
    }
}

# Role-based permissions
permissions = {
    'admin': ['read', 'write', 'delete', 'manage_users'],
    'user': ['read', 'write'],
    'guest': ['read']
}

# Device trust levels (could be dynamically determined)
device_trust = {
    'device_001': 'high',
    'device_002': 'medium',
    'unknown': 'low'
}

# Risk scoring function
def calculate_risk_score(user, device_id, action, resource, context):
    """Calculate risk score based on various factors"""
    score = 0
    
    # User role factor
    if users_db.get(user, {}).get('role') == 'admin':
        score += 10
    elif users_db.get(user, {}).get('role') == 'user':
        score += 30
    else:
        score += 70
    
    # Device trust factor
    if device_trust.get(device_id) == 'high':
        score += 10
    elif device_trust.get(device_id) == 'medium':
        score += 30
    else:
        score += 70
    
    # Action risk (example values)
    action_risk = {'read': 10, 'write': 40, 'delete': 80, 'manage_users': 90}
    score += action_risk.get(action, 50)
    
    # Consider time of access (high risk outside business hours)
    current_hour = datetime.datetime.now().hour
    if 8 <= current_hour <= 18:  # Business hours 8am-6pm
        score += 0
    else:
        score += 30
    
    # Average and normalize
    score = score / 4  # Average of 4 factors
    return min(score, 100)  # Cap at 100

# ----- AUTHENTICATION & AUTHORIZATION -----

def generate_token(username, device_id):
    """Generate JWT token for the user"""
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'iat': datetime.datetime.utcnow(),
        'sub': username,
        'device_id': device_id,
        'jti': str(uuid.uuid4())  # Unique token ID to prevent replay attacks
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    """Decorator for endpoints requiring zero trust verification"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        
        if not token:
            logging.warning('Access attempt without token')
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            username = data['sub']
            device_id = data.get('device_id', 'unknown')
            
            # Verify user exists
            if username not in users_db:
                logging.warning(f'Token with invalid username: {username}')
                return jsonify({'message': 'Invalid token!'}), 401
            
            # Check if device ID matches stored value for extra security
            if device_id != users_db[username].get('device_id', 'unknown'):
                logging.warning(f'Device ID mismatch for user {username}')
                return jsonify({'message': 'Unauthorized device'}), 403
                
            # Store user info in flask g object
            g.user = username
            g.role = users_db[username]['role']
            g.device_id = device_id
            
            # Log successful authentication
            logging.info(f'User {username} authenticated with device {device_id}')
            
        except jwt.ExpiredSignatureError:
            logging.warning('Expired token used')
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            logging.warning('Invalid token used')
            return jsonify({'message': 'Invalid token!'}), 401
            
        return f(*args, **kwargs)
    
    return decorated

def authorize(required_permission):
    """Authorization decorator that implements continuous verification"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            username = g.user
            role = g.role
            device_id = g.device_id
            
            # 1. Check if user has required permission based on role
            if required_permission not in permissions.get(role, []):
                logging.warning(f'User {username} with role {role} attempted unauthorized access to {required_permission}')
                return jsonify({'message': 'Permission denied'}), 403
            
            # 2. Continuous contextual risk assessment
            resource = request.path
            risk_score = calculate_risk_score(username, device_id, required_permission, resource, {
                'ip': request.remote_addr,
                'user_agent': request.user_agent.string,
                'time': datetime.datetime.now().isoformat()
            })
            
            # 3. Apply dynamic authorization based on risk score
            if risk_score > 70:  # High risk
                logging.warning(f'Access denied due to high risk score ({risk_score}) for {username} accessing {resource}')
                return jsonify({'message': 'Access denied due to security policy'}), 403
            
            # Log authorization decision
            logging.info(f'User {username} authorized for {required_permission} on {resource} (risk: {risk_score})')
            
            # Continue to the actual function
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ----- ROUTES -----

@app.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    auth = request.json
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Authentication required'}), 401
        
    username = auth.get('username')
    password = auth.get('password')
    device_id = auth.get('device_id', 'unknown')
    
    # Check if user exists and password is correct
    if username not in users_db or not check_password_hash(users_db[username]['password'], password):
        logging.warning(f'Failed login attempt for user {username}')
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Update device ID if provided
    if device_id != 'unknown':
        users_db[username]['device_id'] = device_id
    
    # Generate token
    token = generate_token(username, users_db[username]['device_id'])
    
    logging.info(f'User {username} logged in from device {device_id}')
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'role': users_db[username]['role']
    })

@app.route('/api/data', methods=['GET'])
@token_required
@authorize('read')
def get_data():
    """Protected endpoint requiring read permission"""
    # In a real application, this would fetch data from a database
    return jsonify({'data': 'This is protected data', 'accessed_by': g.user})

@app.route('/api/data', methods=['POST'])
@token_required
@authorize('write')
def create_data():
    """Protected endpoint requiring write permission"""
    data = request.json
    # In a real application, this would store data in a database
    return jsonify({'message': 'Data created successfully', 'created_by': g.user})

@app.route('/api/admin', methods=['GET'])
@token_required
@authorize('manage_users')
def admin():
    """Admin endpoint requiring manage_users permission"""
    return jsonify({'users': list(users_db.keys()), 'accessed_by': g.user})

@app.route('/health', methods=['GET'])
def health():
    """Unprotected health check endpoint"""
    return jsonify({'status': 'healthy'})

# ----- RUN SERVER -----

if __name__ == '__main__':
    # In production, you would use HTTPS
    # For local testing, we use HTTP but in a real ZTA implementation, 
    # all communication would be encrypted
    app.run(debug=True, host='127.0.0.1', port=5000)