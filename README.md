
# 📘 Student Study Resource Management System

This project is a cloud-based Flask application that allows students and professors to share, manage, and collaborate on study materials. It integrates **AWS services** like **RDS**, **S3**, and **SES** to enable cloud-hosted storage, file uploads, notifications, and secure data management.

---

## 🔧 Technologies Used

| Technology       | Purpose                                                  |
|------------------|----------------------------------------------------------|
| **Python + Flask**  | Backend API development                                |
| **AWS RDS (MySQL)** | Cloud-based relational database for persistent storage |
| **AWS S3**          | File upload and storage for study resources            |
| **AWS SES**         | Email notifications to material owners                 |
| **Postman**         | API Testing                                            |
| **JWT (Flask-JWT)** | Authentication and authorization                       |
| **Bcrypt**          | Password hashing and security                          |

---

## 📂 Features

1. **User Registration & Login**
   - Register students and professors
   - Login with JWT token generation
   - Role-based authorization

2. **Subject Management**
   - Professors can add subjects
   - Public endpoint to view subjects

3. **Study Material Upload**
   - Upload notes (PDF/images), videos, or resource links
   - Files uploaded to AWS S3 and metadata saved to RDS

4. **Comment System**
   - Students can comment on shared materials
   - Notification is sent to the author using AWS SES

5. **Comment Moderation**
   - Professors can mark comments as fixed

---

## 🔐 API Endpoints Overview

| Endpoint                    | Method | Description                               |
|-----------------------------|--------|-------------------------------------------|
| `/register`                | POST   | Register a user                           |
| `/login`                   | POST   | Authenticate user and return JWT          |
| `/subjects`                | GET    | List all available subjects               |
| `/subjects`                | POST   | Add a subject (professor only)            |
| `/upload`                  | POST   | Upload notes/video/link (with form data)  |
| `/materials`               | GET    | List all study materials                  |
| `/comment`                 | POST   | Add a comment to a material               |
| `/comments/<material_id>` | GET    | Get comments for a specific material      |
| `/comments/<comment_id>/fix` | PUT  | Mark comment as fixed (professor only)    |

---

## ✅ How to Run the Project

1. Clone the repository:
   ```
   git clone https://github.com/lcow2419/StudyResourceManagement.git
   cd project-directory
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run the Flask application:
   ```
   python app.py
   ```
 5. Test the funtions using postman. Refer How_To_Test.pdf for the testing.


## 👨‍💻 Contributors

| Name           | Student ID     | Role                            |
|----------------|----------------|---------------------------------|
| Sherin         | c0931539       | File upload + AWS S3            |
| Ansona         | c0932173       | comments + AWS SES              |
| Yashika        | c0933047       | Fixing comments + DB + AWS RDS  |
| Jaiden         | c0933850       | User registration + Login       |
