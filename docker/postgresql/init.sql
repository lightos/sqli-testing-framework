-- SQL Injection Testing Framework - PostgreSQL Schema
-- This schema creates intentionally vulnerable tables for testing

-- Users table - primary injection target
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Products table - for ORDER BY injection tests
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2),
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Logs table - for stacked query tests
-- Note: user_id intentionally lacks a foreign key constraint to allow
-- stacked query injection tests to insert arbitrary log entries without
-- requiring a valid user reference (e.g., INSERT INTO logs ... via injection)
CREATE TABLE logs (
    id SERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    user_id INTEGER,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Sessions table - for authentication bypass tests
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
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

-- Grant necessary permissions for testing
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
