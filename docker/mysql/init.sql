-- SQL Injection Testing Framework - MySQL Schema
-- This schema creates intentionally vulnerable tables for testing

-- Users table - primary injection target
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Products table - for ORDER BY injection tests
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2),
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Logs table - for stacked query tests
-- Note: user_id intentionally lacks a foreign key constraint to allow
-- stacked query injection tests to insert arbitrary log entries without
-- requiring a valid user reference (e.g., INSERT INTO logs ... via injection)
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action TEXT NOT NULL,
    user_id INT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table - for authentication bypass tests
CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert test data
INSERT INTO users (username, password, email, role) VALUES
    ('admin', 'admin123', 'admin@example.com', 'admin'),
    ('user1', 'password1', 'user1@example.com', 'user'),
    ('user2', 'password2', 'user2@example.com', 'user'),
    ('guest', 'guest', 'guest@example.com', 'guest');

INSERT INTO products (name, description, price, category) VALUES
    ('Laptop', 'High-performance laptop', 999.99, 'Electronics'),
    ('Mouse', 'Wireless mouse', 29.99, 'Electronics'),
    ('Keyboard', 'Mechanical keyboard', 79.99, 'Electronics'),
    ('Monitor', '27-inch 4K display', 399.99, 'Electronics'),
    ('Headphones', 'Noise-canceling headphones', 199.99, 'Audio');

INSERT INTO logs (action, user_id, ip_address) VALUES
    ('login', 1, '192.168.1.1'),
    ('view_product', 2, '192.168.1.2'),
    ('logout', 1, '192.168.1.1');

-- Grant permissions (in MySQL, the root user already has full access)
-- Additional users can be created for testing privilege escalation
