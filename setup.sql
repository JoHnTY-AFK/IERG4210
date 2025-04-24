-- Create categories table
CREATE TABLE categories (
    catid INTEGER PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL
);

-- Create products table
CREATE TABLE products (
    pid INTEGER PRIMARY KEY AUTO_INCREMENT,
    catid INTEGER,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    description TEXT,
    image VARCHAR(255),
    thumbnail VARCHAR(255),
    FOREIGN KEY (catid) REFERENCES categories(catid)
);

-- Create users table
CREATE TABLE users (
    userid INTEGER PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    auth_token VARCHAR(255)
);

-- Create orders table
CREATE TABLE orders (
    orderID INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_email VARCHAR(255), -- NULL for guest users
    items JSON NOT NULL, -- Array of {pid, quantity, price}
    total_price DECIMAL(10, 2) NOT NULL,
    digest VARCHAR(64) NOT NULL, -- SHA-256 digest
    status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE SET NULL
);

-- Create transactions table
CREATE TABLE transactions (
    transaction_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    orderID INTEGER NOT NULL,
    paypal_txn_id VARCHAR(255) NOT NULL UNIQUE,
    payment_status VARCHAR(50) NOT NULL,
    payment_amount DECIMAL(10, 2) NOT NULL,
    currency_code VARCHAR(3) NOT NULL,
    payer_email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (orderID) REFERENCES orders(orderID)
);

-- Insert initial data
INSERT INTO categories (name) VALUES ('Hand Cream'), ('Shampoo'), ('Perfume');

INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES
(1, 'Moisturizing Hand Cream', 15.99, 'Hydrates and softens hands', '/images/product1.jpg', '/images/product1_thumb.jpg'),
(1, 'Aloe Vera Hand Cream', 12.99, 'Soothing aloe vera formula', '/images/product2.jpg', '/images/product2_thumb.jpg'),
(2, 'Herbal Shampoo', 9.99, 'Natural herbal ingredients', '/images/product3.jpg', '/images/product3_thumb.jpg'),
(2, 'Anti-Dandruff Shampoo', 11.99, 'Fights dandruff effectively', '/images/product4.jpg', '/images/product4_thumb.jpg'),
(3, 'Floral Perfume', 29.99, 'Long-lasting floral scent', '/images/product5.jpg', '/images/product5_thumb.jpg'),
(3, 'Citrus Perfume', 25.99, 'Fresh citrus fragrance', '/images/product6.jpg', '/images/product6_thumb.jpg'),
(1, 'Shea Butter Hand Cream', 14.99, 'Rich shea butter nourishment', '/images/product7.jpg', '/images/product7_thumb.jpg'),
(2, 'Volumizing Shampoo', 10.99, 'Adds volume to hair', '/images/product8.jpg', '/images/product8_thumb.jpg'),
(3, 'Woody Perfume', 27.99, 'Deep woody notes', '/images/product9.jpg', '/images/product9_thumb.jpg'),
(1, 'Lavender Hand Cream', 13.99, 'Calming lavender scent', '/images/product10.jpg', '/images/product10_thumb.jpg'),
(2, 'Color Protect Shampoo', 12.99, 'Protects colored hair', '/images/product11.jpg', '/images/product11_thumb.jpg'),
(3, 'Ocean Breeze Perfume', 26.99, 'Refreshing ocean scent', '/images/product12.jpg', '/images/product12_thumb.jpg');

INSERT INTO users (email, password, is_admin) VALUES
('admin@example.com', '$2b$10$Ndwr9eo190tkFcXYHrFAaeipj76aGoYtp8gRu9vi1rd7Gd/W8Bhx.', TRUE),
('user@example.com', '$2b$10$7pG43mC8YO2Qe7s1fgxFSe3wM1HM16i3.T9HFWzdZk0cF9fg6wPjG', FALSE);