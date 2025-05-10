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
    firstName VARCHAR(50) NOT NULL,
    lastName VARCHAR(50) NOT NULL,
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

-- Create messages table for chat
CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255),
    message TEXT NOT NULL,
    response TEXT,
    status ENUM('pending', 'responded') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP NULL,
    seen TINYINT DEFAULT 0,
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE SET NULL
);

-- Create verification_codes table for email verification
CREATE TABLE verification_codes (
    code_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(6) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
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
(3, 'Ocean Breeze Perfume', 129.99, 'Eau De Parfume, Black Sakura, Unveil your signature scent with timeless elegance in every drop', '/images/product12.jpg', '/images/product12.jpg'),
(1, 'Rose Hand Cream', 59.99, 'Hydrating Rose Cream 100mL', '/images/product13.jpg', '/images/product13.jpg'),
(1, 'Coconut Hand Cream', 69.99, 'Nourishing Coconut Cream 50mL', '/images/product14.jpg', '/images/product14.jpg'),
(1, 'Chamomile Hand Cream', 79.99, 'Calming Chamomile Cream 75mL', '/images/product15.jpg', '/images/product15.jpg'),
(1, 'Honey Hand Cream', 89.99, 'Moisturizing Honey Cream 100mL', '/images/product16.jpg', '/images/product16.jpg'),
(1, 'Almond Hand Cream', 99.99, 'Rich Almond Cream 50mL', '/images/product17.jpg', '/images/product17.jpg'),
(1, 'Vanilla Hand Cream', 109.99, 'Smooth Vanilla Cream 75mL', '/images/product18.jpg', '/images/product18.jpg'),
(1, 'Peppermint Hand Cream', 119.99, 'Cooling Peppermint Cream 100mL', '/images/product19.jpg', '/images/product19.jpg'),
(1, 'Green Tea Hand Cream', 129.99, 'Antioxidant Green Tea Cream 50mL', '/images/product20.jpg', '/images/product20.jpg'),
(2, 'Moisturizing Shampoo', 99.99, 'Hydrating Shampoo for Dry Hair 300mL', '/images/product21.jpg', '/images/product21.jpg'),
(2, 'Clarifying Shampoo', 109.99, 'Deep Cleansing Shampoo 250mL', '/images/product22.jpg', '/images/product22.jpg'),
(2, 'Smoothing Shampoo', 119.99, 'Frizz-Control Shampoo 300mL', '/images/product23.jpg', '/images/product23.jpg'),
(2, 'Strengthening Shampoo', 129.99, 'Keratin-Infused Shampoo 250mL', '/images/product24.jpg', '/images/product24.jpg'),
(2, 'Coconut Oil Shampoo', 139.99, 'Nourishing Coconut Shampoo 300mL', '/images/product25.jpg', '/images/product25.jpg'),
(2, 'Argan Oil Shampoo', 149.99, 'Restorative Argan Shampoo 250mL', '/images/product26.jpg', '/images/product26.jpg'),
(2, 'Tea Tree Shampoo', 159.99, 'Scalp-Soothing Tea Tree Shampoo 300mL', '/images/product27.jpg', '/images/product27.jpg'),
(2, 'Biotin Shampoo', 169.99, 'Hair Growth Shampoo 250mL', '/images/product28.jpg', '/images/product28.jpg'),
(3, 'Rose Perfume', 139.99, 'Elegant Rose Eau de Parfum 50mL', '/images/product29.jpg', '/images/product29.jpg'),
(3, 'Lavender Perfume', 149.99, 'Calming Lavender Scent 75mL', '/images/product30.jpg', '/images/product30.jpg'),
(3, 'Vanilla Perfume', 159.99, 'Warm Vanilla Fragrance 50mL', '/images/product31.jpg', '/images/product31.jpg'),
(3, 'Sandalwood Perfume', 169.99, 'Rich Sandalwood Eau de Parfum 75mL', '/images/product32.jpg', '/images/product32.jpg'),
(3, 'Jasmine Perfume', 179.99, 'Exotic Jasmine Scent 50mL', '/images/product33.jpg', '/images/product33.jpg'),
(3, 'Musk Perfume', 189.99, 'Bold Musk Fragrance 75mL', '/images/product34.jpg', '/images/product34.jpg'),
(3, 'Amber Perfume', 199.99, 'Warm Amber Eau de Parfum 50mL', '/images/product35.jpg', '/images/product35.jpg'),
(3, 'Oud Perfume', 209.99, 'Luxury Oud Scent 75mL', '/images/product36.jpg', '/images/product36.jpg');

-- Insert initial users (passwords hashed with bcrypt)
INSERT INTO users (email, firstName, lastName, password, is_admin) VALUES
('admin@example.com', 'Admin', 'User', '$2b$10$Ndwr9eo190tkFcXYHrFAaeipj76aGoYtp8gRu9vi1rd7Gd/W8Bhx.', TRUE),
('user@example.com', 'John', 'Doe', '$2b$10$7pG43mC8YO2Qe7s1fgxFSe3wM1HM16i3.T9HFWzdZk0cF9fg6wPjG', FALSE),
('testing6070@example.com', 'Test', 'User', '$2b$10$BrD1MfYbkFTJ5u6PfmBVGuzpOHSbh3FI2IgLBk./tv0oujXemR2Ra', FALSE);

-- Add seen column to messages table
ALTER TABLE messages ADD seen TINYINT DEFAULT 0;