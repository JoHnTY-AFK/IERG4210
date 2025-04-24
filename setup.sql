-- Create database
CREATE DATABASE IF NOT EXISTS shopping_db;
USE shopping_db;

-- Create categories table
CREATE TABLE categories (
    catid INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

-- Create products table
CREATE TABLE products (
    pid INT AUTO_INCREMENT PRIMARY KEY,
    catid INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    image VARCHAR(255),
    thumbnail VARCHAR(255),
    FOREIGN KEY (catid) REFERENCES categories(catid)
);

-- Create users table
CREATE TABLE users (
    userid INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    auth_token VARCHAR(255)
);

-- Create orders table
CREATE TABLE orders (
    orderID INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255),
    items JSON NOT NULL,
    total_price DECIMAL(10,2) NOT NULL,
    digest VARCHAR(255) NOT NULL,
    status ENUM('pending', 'completed', 'failed') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE SET NULL
);

-- Create transactions table
CREATE TABLE transactions (
    transaction_id INT AUTO_INCREMENT PRIMARY KEY,
    orderID INT NOT NULL,
    paypal_txn_id VARCHAR(255) NOT NULL,
    payment_status VARCHAR(50) NOT NULL,
    payment_amount DECIMAL(10,2) NOT NULL,
    currency_code VARCHAR(10) NOT NULL,
    payer_email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (orderID) REFERENCES orders(orderID)
);

-- Insert initial categories
INSERT INTO categories (name) VALUES
('Hand Cream'),
('Shampoo'),
('Perfume');

-- Insert initial products
INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES
(1, 'Moisturizing Hand Cream', 10.99, 'A rich, non-greasy hand cream for soft hands.', '/images/product1.jpg', '/images/product1.jpg'),
(1, 'Aloe Vera Hand Cream', 12.99, 'Hydrates and soothes dry skin.', '/images/product2.jpg', '/images/product2.jpg'),
(1, 'Shea Butter Hand Cream', 11.99, 'Nourishes and protects hands.', '/images/product3.jpg', '/images/product3.jpg'),
(1, 'Lavender Hand Cream', 13.99, 'Calming scent with deep hydration.', '/images/product4.jpg', '/images/product4.jpg'),
(2, 'Herbal Shampoo', 8.99, 'Gentle cleansing for all hair types.', '/images/product5.jpg', '/images/product5.jpg'),
(2, 'Anti-Dandruff Shampoo', 9.99, 'Fights dandruff and soothes scalp.', '/images/product6.jpg', '/images/product6.jpg'),
(2, 'Volumizing Shampoo', 10.99, 'Adds volume and shine.', '/images/product7.jpg', '/images/product7.jpg'),
(2, 'Color-Protect Shampoo', 11.99, 'Protects colored hair.', '/images/product8.jpg', '/images/product8.jpg'),
(3, 'Floral Perfume', 19.99, 'A light, floral fragrance.', '/images/product9.jpg', '/images/product9.jpg'),
(3, 'Citrus Perfume', 21.99, 'Fresh and zesty scent.', '/images/product10.jpg', '/images/product10.jpg'),
(3, 'Woody Perfume', 23.99, 'Warm and earthy notes.', '/images/product11.jpg', '/images/product11.jpg'),
(3, 'Ocean Breeze Perfume', 20.99, 'Cool and refreshing fragrance.', '/images/product12.jpg', '/images/product12.jpg');

-- Insert initial users (passwords hashed with bcrypt)
INSERT INTO users (email, password, is_admin) VALUES
('admin@example.com', '$2b$10$Ndwr9eo190tkFcXYHrFAaeipj76aGoYtp8gRu9vi1rd7Gd/W8Bhx.', TRUE),
('user@example.com', '$2b$10$7pG43mC8YO2Qe7s1fgxFSe3wM1HM16i3.T9HFWzdZk0cF9fg6wPjG', FALSE);