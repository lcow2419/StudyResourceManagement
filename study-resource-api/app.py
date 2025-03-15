from flask import Flask, jsonify, request
import mysql.connector
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Database Connection
try:
    db = mysql.connector.connect(
        host="studyresourcedb.c34mmak0gyrv.ca-central-1.rds.amazonaws.com",
        user="sfarjana",
        password="Adithya2511",
        database="studyresourcedb"
    )
    cursor = db.cursor(dictionary=True)
    print("Database connection successful!")
except mysql.connector.Error as err:
    print(f"Error connecting to database: {err}")

@app.route('/')
def home():
    return jsonify({"message": "Study Resource Management System API is running"})

if __name__ == "__main__":
    app.run(debug=True)
