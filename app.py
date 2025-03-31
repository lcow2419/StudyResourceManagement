import os
import boto3
import pymysql
import pymysql.cursors
import mysql.connector
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask import request, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity





# Load environment variables
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

# Initialize Flask app
app = Flask(__name__)
bcrypt = Bcrypt(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")  # Load JWT secret from .env
jwt = JWTManager(app)

# AWS S3 Configuration
s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_REGION"),
)

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
    """
    Endpoint to register a new user.

    - Accepts JSON input: { "name": "...", "email": "...", "password": "...", "role": "student/professor" }
    - Validates that all fields are provided.
    - Ensures 'role' is either 'student' or 'professor'.
    - Hashes the password before storing it for security.
    - Inserts the user data into the 'users' table in MySQL.
    - Returns success or error response.
    """

    # Extract JSON data from request
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    # Validate the 'role' field
    if role not in ['student', 'professor']:
        return jsonify({"error": "Invalid role"}), 400

    # Hash the password for security
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    print(f"Hashed Password: {hashed_password}")  # Debugging print statement

    # Get database connection
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with db.cursor() as cursor:
            # Insert user into database
            cursor.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
                           (name, email, hashed_password, role))
            db.commit()
            return jsonify({"message": "User registered successfully"}), 201

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500  # Return MySQL error message if insertion fails

    finally:
        db.close()  # Close the database connection

# ---------------------------
# USER LOGIN ROUTE
# ---------------------------
@app.route('/login', methods=['POST'])
def login():
    """Handles user login by verifying email and password."""
    
    # Get the JSON data from the request
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Establish a connection to the database
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500  # Return error if DB connection fails

    try:
        with db.cursor(dictionary=True) as cursor:
            # Query the database to check if the user exists
            cursor.execute("SELECT user_id, name, password, role FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            # If no user is found, return an error
            if not user:
                return jsonify({"error": "Invalid email or password"}), 401

            # Verify the provided password against the hashed password stored in the database
            if not bcrypt.check_password_hash(user['password'], password):
                return jsonify({"error": "Invalid email or password"}), 401  # Return error for incorrect password

            # Generate a JWT (JSON Web Token) for authenticated user
            access_token = create_access_token(identity={'user_id': user['user_id'], 'role': user['role']})

            # Return success response with user details and token
            return jsonify({
                "message": "Login successful",
                "access_token": access_token,
                "user": {
                    "user_id": user['user_id'],
                    "name": user['name'],
                    "role": user['role']
                }
            }), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500  # Return error if a database query fails
    finally:
        db.close()  # Ensure database connection is closed after the operation

# ---------------------------
# PROTECTED ROUTE (Requires Authentication)
# ---------------------------
@app.route('/protected', methods=['GET'])
@jwt_required()  # Ensures that the user must provide a valid JWT token
def protected():
    """
    This route is protected and can only be accessed by authenticated users.
    It extracts the currently logged-in user's identity from the JWT token.
    """
    current_user = get_jwt_identity()  # Retrieves user details from the JWT
    return jsonify({"message": "Welcome!", "user": current_user}), 200  # Responds with the user details
    
# ---------------------------
# GET SUBJECTS ROUTE
# ---------------------------
@app.route("/subjects", methods=["GET"])
def get_subjects():
    """
    Retrieves the list of subjects from the database.
    No authentication is required.
    """
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500  # Return error if DB connection fails

    try:
        with db.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM subjects")  # Fetch all subjects
            subjects = cursor.fetchall()
            return jsonify(subjects), 200  # Return the list of subjects as JSON
    finally:
        db.close()  # Ensure the database connection is closed

# ---------------------------
# ADD SUBJECT ROUTE
# ---------------------------
@app.route("/subjects", methods=["POST"])
def add_subject():
    """
    Allows only professors to add new subjects.
    """
    data = request.json
    user_id = data.get("user_id")  # Manually provided user ID
    subject_name = data.get("subject_name")
    
    # Validate inputs
    if not user_id or not isinstance(user_id, int):
        return jsonify({"error": "Invalid user ID"}), 400
    if not isinstance(subject_name, str) or not subject_name.strip():
        return jsonify({"error": "Invalid subject name"}), 400
    
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500
    
    try:
        with db.cursor(dictionary=True) as cursor:
            # Check if user is a professor
            cursor.execute("SELECT role FROM users WHERE user_id = %s", (user_id,))
            user = cursor.fetchone()
            if not user or user["role"] != "professor":
                return jsonify({"error": "Unauthorized"}), 403

            # Insert subject into database
            cursor.execute("INSERT INTO subjects (subject_name) VALUES (%s)", (subject_name,))
            db.commit()  # Save changes
            return jsonify({"message": "Subject added successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500  # Handle DB errors
    finally:
        db.close()  # Close DB connection


# AWS S3 Config
S3_BUCKET = os.getenv("S3_BUCKET_NAME")
S3_REGION = os.getenv("AWS_REGION")
s3 = boto3.client("s3")

# Allowed file types
ALLOWED_EXTENSIONS = {"pdf", "mp4", "jpg", "png"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------------------
# STUDY MATERIAL ROUTES
# ---------------------------

# Retrieve All Study Materials (with file links)
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


# Upload Study Material (Manually Enter User ID)
@app.route("/upload", methods=["POST"])
def upload_material():
    user_id = request.form.get("user_id")  # Manually entered user ID
    subject_id = request.form.get("subject_id")
    material_type = request.form.get("material_type")
    material_link = request.form.get("material_link")  # Only for 'link' type

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    if material_type not in ["notes", "video", "link"]:
        return jsonify({"error": "Invalid material type"}), 400

    # Database Connection
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        file_url = None

        # If it's a link, save directly
        if material_type == "link":
            file_url = material_link

        # If it's a file (notes or video), upload to S3
        else:
            if "file" not in request.files:
                return jsonify({"error": "No file provided"}), 400

            file = request.files["file"]
            if file.filename == "":
                return jsonify({"error": "No selected file"}), 400

            if not allowed_file(file.filename):
                return jsonify({"error": "Invalid file type"}), 400

            # Secure filename and upload to S3
            filename = secure_filename(file.filename)
            s3.upload_fileobj(file, S3_BUCKET, filename)
            file_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"

        # Insert record into RDS
        with db.cursor() as cursor:
            cursor.execute(
                "INSERT INTO studymaterials (user_id, subject_id, material_type, material_link, file_url) VALUES (%s, %s, %s, %s, %s)",
                (user_id, subject_id, material_type, material_link, file_url)
            )
            db.commit()

        return jsonify({"message": "Material added successfully!", "file_url": file_url}), 201

    except pymysql.MySQLError as err:
        return jsonify({"error": str(err)}), 500
    finally:
        db.close()  
        
# Initialize AWS SES Client
ses_client = boto3.client("ses", region_name="ca-central-1")  

# Sender Email (Must be verified in AWS SES)
SES_SENDER_EMAIL = "sherinfarjana.siraj@gmail.com"

def send_email_notification_with_ses(owner_email, comment_text):
    """
    Sends an email notification to the material owner using AWS SES.
    """
    try:
        response = ses_client.send_email(
            Source=SES_SENDER_EMAIL,  # Verified sender email
            Destination={
                "ToAddresses": [owner_email],  # Owner's email (must be verified if in sandbox)
            },
            Message={
                "Subject": {"Data": "New Comment on Your Study Material"},
                "Body": {
                    "Text": {"Data": f"A new comment has been added to your study material:\n\n{comment_text}\n\nPlease check it!"}
                },
            },
        )
        return response
    except Exception as e:
        return {"error": str(e)}

@app.route("/comment", methods=["POST"])
def add_comment():
    """
    Adds a comment to a study material and notifies only the material owner via AWS SES Email.
    """
    data = request.json
    material_id = data.get("material_id")
    user_id = data.get("user_id")
    comment_text = data.get("comment")

    if not material_id or not user_id or not comment_text:
        return jsonify({"error": "Missing required fields"}), 400

    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = db.cursor()

    try:
        # Fetch study material owner ID
        cursor.execute("SELECT user_id FROM studymaterials WHERE material_id = %s", (material_id,))
        owner_id = cursor.fetchone()
        
        if not owner_id:
            return jsonify({"error": "Material not found"}), 404
        owner_id = owner_id[0]  # Extract user_id from tuple

        # Fetch owner's email
        cursor.execute("SELECT email FROM users WHERE user_id = %s", (owner_id,))
        owner_email = cursor.fetchone()
        
        if not owner_email:
            return jsonify({"error": "Material owner not found"}), 404
        owner_email = owner_email[0]  # Extract email from tuple

        # Insert comment into the database with default status 'unfixed'
        cursor.execute(
            "INSERT INTO comments (material_id, user_id, comment_text, status) VALUES (%s, %s, %s, 'unfixed')",
            (material_id, user_id, comment_text),
        )
        db.commit()

        # Send Direct Email Notification to the Material Owner using SES
        ses_response = send_email_notification_with_ses(owner_email, comment_text)

        return jsonify({"message": "Comment added and notification sent!", "ses_response": ses_response}), 201

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        db.close()

@app.route("/comments/<int:material_id>", methods=["GET"])
def get_comments(material_id):
    """
    Retrieves all comments for a specific study material based on material_id.
    """
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM comments WHERE material_id = %s", (material_id,))
        comments = cursor.fetchall()
        
        if not comments:
            return jsonify({"message": "No comments found for this material"}), 404

        return jsonify(comments), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        db.close()

    
    
    
    

@app.route("/comments/<int:comment_id>/fix", methods=["PUT"])
def mark_comment_fixed(comment_id):
    """
    Manually enter user_id to mark a comment as fixed.
    Only professors (role='professor') can do this.
    """
    data = request.json
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = db.cursor()

    try:
        # Check if the user is a professor
        cursor.execute("SELECT role FROM users WHERE user_id = %s", (user_id,))
        user_role = cursor.fetchone()

        if not user_role:
            return jsonify({"error": "User not found"}), 404
        
        if user_role[0] != "professor":
            return jsonify({"error": "Only professors can mark comments as fixed"}), 403

        # Update the comment status to 'fixed'
        cursor.execute("UPDATE comments SET status = 'fixed' WHERE comment_id = %s", (comment_id,))
        db.commit()

        return jsonify({"message": "Comment marked as fixed"}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        db.close()
    
# ---------------------------
# RUN FLASK APP
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)
