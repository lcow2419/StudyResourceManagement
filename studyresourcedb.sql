-- Create database
CREATE DATABASE IF NOT EXISTS studyresourcedb;
USE studyresourcedb;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('student', 'professor') NOT NULL
);

-- Create subjects table
CREATE TABLE IF NOT EXISTS subjects (
    subject_id INT AUTO_INCREMENT PRIMARY KEY,
    subject_name VARCHAR(100) NOT NULL UNIQUE
);

-- Create studymaterials table
CREATE TABLE IF NOT EXISTS studymaterials (
    material_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    subject_id INT,
    material_type ENUM('notes', 'video', 'link') NOT NULL,
    material_link TEXT NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_url VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (subject_id) REFERENCES subjects(subject_id)
);

-- Create comments table
CREATE TABLE IF NOT EXISTS comments (
    comment_id INT AUTO_INCREMENT PRIMARY KEY,
    material_id INT NOT NULL,
    user_id INT NOT NULL,
    comment_text TEXT NOT NULL,
    status ENUM('unfixed', 'fixed') DEFAULT 'unfixed',
    FOREIGN KEY (material_id) REFERENCES studymaterials(material_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
