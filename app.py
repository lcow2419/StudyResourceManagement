from flask import Flask, request, jsonify
import mysql.connector
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from dotenv import load_dotenv

# Load environment variables
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

# Initialize Flask app
app = Flask(__name__)
bcrypt = Bcrypt(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")  # Load JWT secret from .env
jwt = JWTManager(app)

# Debug: Verify JWT secret key is loaded
print(f"JWT_SECRET_KEY Loaded: {app.config['JWT_SECRET_KEY']}")

# Function to establish a database connection
def get_db_connection():
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            auth_plugin="caching_sha2_password"
        )
    except mysql.connector.Error as err:
        print(f"Database Connection Error: {err}")
        return None

# ---------------------------
# HOME ROUTE
# ---------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Welcome to the Student Study Resource Management System"}), 200

# ---------------------------
# USER REGISTRATION ROUTE
# ---------------------------
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    if role not in ['student', 'professor']:
        return jsonify({"error": "Invalid role"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    print(f"Hashed Password: {hashed_password}") 

    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with db.cursor() as cursor:
            cursor.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
                           (name, email, hashed_password, role))
            db.commit()
            return jsonify({"message": "User registered successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        db.close()

# ---------------------------
# USER LOGIN ROUTE
# ---------------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with db.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT user_id, password, role FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
        
        if user:
            print(f"Stored Hash: {user['password']}")
            print(f"Entered Password: {password}")
            print(f"Hash Match: {bcrypt.check_password_hash(user['password'], password)}")


        if user and bcrypt.check_password_hash(user['password'], password):
            access_token = create_access_token(identity={"id": user['user_id'], "role": user['role']})
            return jsonify({"access_token": access_token, "role": user['role']}), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 401
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        db.close()

# ---------------------------
# PROTECTED ROUTE (Requires Authentication)
# ---------------------------
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": "Welcome!", "user": current_user}), 200

# ---------------------------
# SUBJECT ROUTES
# ---------------------------
@app.route("/subjects", methods=["GET"])
def get_subjects():
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with db.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM subjects")
            subjects = cursor.fetchall()
            return jsonify(subjects), 200
    finally:
        db.close()

@app.route("/subjects", methods=["POST"])
@jwt_required()
def add_subject():
    current_user = get_jwt_identity()
    if current_user['role'] != 'professor':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    subject_name = data.get("subject_name")

    if not isinstance(subject_name, str) or not subject_name.strip():
        return jsonify({"error": "Invalid subject name"}), 400

    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with db.cursor() as cursor:
            cursor.execute("INSERT INTO subjects (subject_name) VALUES (%s)", (subject_name,))
            db.commit()
            return jsonify({"message": "Subject added successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        db.close()

# ---------------------------
# STUDY MATERIAL ROUTES
# ---------------------------
@app.route("/materials", methods=["GET"])
def get_materials():
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with db.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM studymaterials")
            materials = cursor.fetchall()
            return jsonify(materials), 200
    finally:
        db.close()

@app.route("/materials", methods=["POST"])
@jwt_required()
def add_material():
    current_user = get_jwt_identity()
    data = request.json
    user_id = current_user["id"]
    subject_id = data.get("subject_id")
    material_type = data.get("material_type")
    material_link = data.get("material_link")

    if material_type not in ['notes', 'video', 'link']:
        return jsonify({"error": "Invalid material type"}), 400

    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with db.cursor() as cursor:
            cursor.execute("INSERT INTO studymaterials (user_id, subject_id, material_type, material_link) VALUES (%s, %s, %s, %s)",
                           (user_id, subject_id, material_type, material_link))
            db.commit()
            return jsonify({"message": "Material added successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        db.close()
        
# ---------------------------
# COMMENTS ROUTES
# ---------------------------
@app.route("/comments", methods=["POST"])
@jwt_required()
def add_comment():
    current_user = get_jwt_identity()
    data = request.json
    material_id = data.get("material_id")
    comment_text = data.get("comment_text")
    
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO comments (material_id, user_id, comment_text) VALUES (%s, %s, %s)",
                       (material_id, current_user['id'], comment_text))
        db.commit()
        return jsonify({"message": "Comment added successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        db.close()

@app.route("/comments/<int:material_id>", methods=["GET"])
def get_comments(material_id):
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM comments WHERE material_id = %s", (material_id,))
    comments = cursor.fetchall()
    cursor.close()
    db.close()
    return jsonify(comments), 200

@app.route("/comments/<int:comment_id>/fix", methods=["PUT"])
@jwt_required()
def mark_comment_fixed(comment_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'professor':
        return jsonify({"error": "Only professors can mark comments as fixed"}), 403
    
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE comments SET status = 'fixed' WHERE comment_id = %s", (comment_id,))
        db.commit()
        return jsonify({"message": "Comment marked as fixed"}), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        db.close()

# ---------------------------
# RUN FLASK APP
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)
