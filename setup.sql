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
    salt VARCHAR(32) NOT NULL,
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
    items JSON NOT NULL,
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
(1, 'Moisturizing Hand Cream', 19.99, 'Daily Cream 100mL', '/images/product1.jpg', '/images/product1.jpg'),
(2, 'Aloe Vera Hand Cream', 29.99, 'Borcelle 50mL', '/images/product2.jpg', '/images/product2.jpg'),
(3, 'Shea Butter Hand Cream', 39.99, 'Special Sale Parfume, Up to 25% off', '/images/product3.jpg', '/images/product3.jpg'),
(3, 'Lavender Hand Cream', 49.99, 'Special Sale Perfume', '/images/product4.jpg', '/images/product4.jpg'),
(2, 'Herbal Shampoo', 59.99, 'Studio Shodwe Haircare, Refreshing Scalp Shampoo, Anti-Dandruff, 250mL / 8.4 fl oz', '/images/product5.jpg', '/images/product5.jpg'),
(2, 'Anti-Dandruff Shampoo', 69.99, 'Arowwai Industries, Volume Boost Shampoo, For fine and limp hair, 250mL / 8.4 fl oz', '/images/product6.jpg', '/images/product6.jpg'),
(3, 'Volumizing Shampoo', 79.99, 'Luxury Perfume', '/images/product7.jpg', '/images/product7.jpg'),
(3, 'Color-Protect Shampoo', 89.99, 'Special Offer Perfume, Up to 25% off', '/images/product8.jpg', '/images/product8.jpg'),
(3, 'Floral Perfume', 99.99, 'Perfect Perfume', '/images/product9.jpg', '/images/product9.jpg'),
(3, 'Citrus Perfume', 109.99, 'Liceria & Co., New Perfume, Fresh Blossoms of the Spring', '/images/product10.jpg', '/images/product10.jpg'),
(3, 'Woody Perfume', 119.99, 'Gold Perfume Luxury Collection, Fragrant and Fresh, Borcelle, 150mL', '/images/product11.jpg', '/images/product11.jpg'),
(3, 'Ocean Breeze Perfume', 129.99, 'Eau De Parfume, Black Sakura, Unveil your signature scent with timeless elegance in every drop', '/images/product12.jpg', '/images/product12.jpg');

-- Insert initial users (passwords hashed with bcrypt)
INSERT INTO users (email, password, is_admin) VALUES
('admin@example.com', '$2b$10$Ndwr9eo190tkFcXYHrFAaeipj76aGoYtp8gRu9vi1rd7Gd/W8Bhx.', TRUE),
('user@example.com', '$2b$10$7pG43mC8YO2Qe7s1fgxFSe3wM1HM16i3.T9HFWzdZk0cF9fg6wPjG', FALSE),
{'testing6070@example.com', '$2b$10$BrD1MfYbkFTJ5u6PfmBVGuzpOHSbh3FI2IgLBk./tv0oujXemR2Ra', FALSE};
