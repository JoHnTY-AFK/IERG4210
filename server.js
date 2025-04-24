const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const path = require('path');
const multer = require('multer');
const sharp = require('sharp');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const sanitizeHtml = require('sanitize-html');
const http = require('http');
const dotenv = require('dotenv');
dotenv.config();

const fs = require('fs');

const app = express();
const upload = multer({ dest: 'uploads/', limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB limit

const db = mysql.createPool({
    host: process.env.DB_HOST || 'ierg4210.mysql.database.azure.com',
    user: process.env.DB_USER || 'admin1',
    password: process.env.DB_PASSWORD || 'Fd&5cb4VZ',
    database: process.env.DB_NAME || 'shopping_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: {
        rejectUnauthorized: true,
        ca: fs.readFileSync("./DigiCertGlobalRootCA.crt.pem", "utf8"),
    }
});

// Add this right after creating the pool
db.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1);
    }
    console.log('Database connected successfully');
    connection.release();
});

// Middleware
app.use(cors({
    origin: 'https://ierg4210.koreacentral.cloudapp.azure.com',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public'))); // Serve public directory
app.use(express.static(__dirname, { index: false })); // Serve root, disable default index

// CSRF Protection
const generateCsrfToken = () => crypto.randomBytes(16).toString('hex');
app.use((req, res, next) => {
    if (!req.cookies.csrfToken) {
        const token = generateCsrfToken();
        res.cookie('csrfToken', token, { httpOnly: true, secure: true, sameSite: 'strict' });
    }
    next();
});

const validateCsrfToken = (req, res, next) => {
    const csrfToken = req.cookies.csrfToken;
    const bodyToken = req.body.csrfToken || req.headers['x-csrf-token'];
    if (!csrfToken || !bodyToken || csrfToken !== bodyToken) {
        return res.status(403).send('CSRF token validation failed');
    }
    next();
};

// Authentication Middleware
const authenticate = async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) return res.redirect('/login');
        
        const [results] = await db.query('SELECT * FROM users WHERE auth_token = ?', [authToken]);
        if (!results.length) return res.redirect('/login');
        
        req.user = results[0];
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).send('Internal Server Error');
    }
};

const isAdmin = (req, res, next) => {
    if (!req.user || !req.user.is_admin) return res.status(403).send('Admin access required');
    next();
};

// Input Validation
const validateTextInput = (text, maxLength, fieldName) => {
    if (!text || typeof text !== 'string') return `${fieldName} is required`;
    if (text.length > maxLength) return `${fieldName} must be ${maxLength} characters or less`;
    if (!/^[a-zA-Z0-9\s\-,.]+$/.test(text)) return `${fieldName} contains invalid characters`;
    return null;
};

const validatePrice = (price) => {
    const num = parseFloat(price);
    if (isNaN(num) || num < 0) return 'Price must be a non-negative number';
    return null;
};

// Escape HTML function
const escapeHtml = (text) => sanitizeHtml(text, { allowedTags: [], allowedAttributes: {} });

// Routes for HTML pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/product', (req, res) => {
    res.sendFile(path.join(__dirname, 'product.html'));
});

app.get('/admin', authenticate, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Block direct access to /public/admin.html
app.get('/public/admin.html', (req, res) => {
    res.redirect('/login');
});

// API Routes
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.cookies.csrfToken });
});

app.get('/user', async (req, res) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) return res.json({ email: 'Guest', isAdmin: false });
        
        const [results] = await db.query('SELECT email, is_admin FROM users WHERE auth_token = ?', [authToken]);
        if (!results.length) return res.json({ email: 'Guest', isAdmin: false });
        
        res.json({ email: results[0].email, isAdmin: results[0].is_admin });
    } catch (err) {
        console.error('User fetch error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/categories', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM categories');
        res.json(results.map(row => ({ catid: row.catid, name: escapeHtml(row.name) })));
    } catch (err) {
        console.error('Categories error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/products', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM products');
        res.json(results.map(row => ({
            pid: row.pid,
            catid: row.catid,
            name: escapeHtml(row.name),
            price: row.price,
            description: escapeHtml(row.description),
            image: row.image,
            thumbnail: row.thumbnail
        })));
    } catch (err) {
        console.error('Products error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/products/:catid', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM products WHERE catid = ?', [req.params.catid]);
        res.json(results.map(row => ({
            pid: row.pid,
            catid: row.catid,
            name: escapeHtml(row.name),
            price: row.price,
            description: escapeHtml(row.description),
            image: row.image,
            thumbnail: row.thumbnail
        })));
    } catch (err) {
        console.error('Products by catid error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/product/:pid', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM products WHERE pid = ?', [req.params.pid]);
        const product = results[0] || {};
        res.json({
            pid: product.pid,
            name: escapeHtml(product.name || ''),
            price: product.price || 0,
            description: escapeHtml(product.description || ''),
            image: product.image || ''
        });
    } catch (err) {
        console.error('Product error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/login', validateCsrfToken, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Get a connection from the pool
        const connection = await db.getConnection();
        
        try {
            // Execute query using promise interface
            const [users] = await connection.query(
                'SELECT userid, email, password, is_admin FROM users WHERE email = ?', 
                [email]
            );

            if (users.length === 0) {
                connection.release();
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const user = users[0];
            const match = await bcrypt.compare(password, user.password);
            
            if (!match) {
                connection.release();
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const authToken = crypto.randomBytes(32).toString('hex');
            
            await connection.query(
                'UPDATE users SET auth_token = ? WHERE userid = ?',
                [authToken, user.userid]
            );

            connection.release();

            res.cookie('authToken', authToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 2 * 24 * 60 * 60 * 1000,
                path: '/'
            });

            res.json({ 
                role: user.is_admin ? 'admin' : 'user',
                redirect: user.is_admin ? '/admin' : '/',
                email: user.email
            });

        } catch (err) {
            connection.release();
            console.error('Login error:', err.stack);
            res.status(500).json({ 
                error: 'Internal server error',
                details: process.env.NODE_ENV === 'development' ? err.message : null
            });
        }
    } catch (err) {
        console.error('Connection error:', err.stack);
        res.status(500).json({ 
            error: 'Internal server error',
            details: process.env.NODE_ENV === 'development' ? err.message : null
        });
    }
});

app.post('/logout', validateCsrfToken, authenticate, async (req, res) => {
    try {
        await db.query('UPDATE users SET auth_token = NULL WHERE userid = ?', [req.user.userid]);
        res.clearCookie('authToken');
        
        // Generate a NEW CSRF token immediately after logout
        const newCsrfToken = generateCsrfToken();
        res.cookie('csrfToken', newCsrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict' 
        });
        
        res.json({ 
            success: true, 
            redirect: '/login',
            csrfToken: newCsrfToken
        });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/change-password', validateCsrfToken, authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword || newPassword.length < 8) {
            return res.status(400).send('Invalid input: New password must be at least 8 characters');
        }

        const match = await bcrypt.compare(currentPassword, req.user.password);
        if (!match) return res.status(401).send('Current password incorrect');
        
        const hash = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = ?, auth_token = NULL WHERE userid = ?', [hash, req.user.userid]);
        
        res.clearCookie('authToken');
        res.clearCookie('csrfToken');
        res.redirect('/login');
    } catch (err) {
        console.error('Password change error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/add-product', validateCsrfToken, authenticate, isAdmin, upload.single('image'), async (req, res) => {
    const { catid, name, price, description } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    // Validate inputs
    const nameError = validateTextInput(name, 255, 'Product name');
    const descError = validateTextInput(description, 1000, 'Description');
    const priceError = validatePrice(price);
    if (nameError || descError || priceError || !catid) {
        return res.status(400).send(nameError || descError || priceError || 'Category ID is required');
    }

    const sanitizedName = sanitizeHtml(name);
    const sanitizedDesc = sanitizeHtml(description);

    if (imagePath) {
        // Validate image mime type
        if (!['image/jpeg', 'image/png', 'image/gif'].includes(req.file.mimetype)) {
            return res.status(400).send('Invalid image type. Only JPEG, PNG, or GIF allowed.');
        }

        sharp(req.file.path)
            .resize(200, 200)
            .toFile(`uploads/thumbnail-${req.file.filename}`, (err) => {
                if (err) {
                    console.error('Image resize error:', err);
                    return res.status(500).send('Internal Server Error');
                }
                const thumbnailPath = `/uploads/thumbnail-${req.file.filename}`;
                const sql = 'INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES (?, ?, ?, ?, ?, ?)';
                db.query(sql, [catid, sanitizedName, price, sanitizedDesc, imagePath, thumbnailPath], (err) => {
                    if (err) {
                        console.error('Add product error:', err);
                        return res.status(500).send('Internal Server Error');
                    }
                    res.send('Product added');
                });
            });
    } else {
        const sql = 'INSERT INTO products (catid, name, price, description) VALUES (?, ?, ?, ?)';
        db.query(sql, [catid, sanitizedName, price, sanitizedDesc], (err) => {
            if (err) {
                console.error('Add product error:', err);
                return res.status(500).send('Internal Server Error');
            }
            res.send('Product added');
        });
    }
});

app.put('/update-product/:pid', validateCsrfToken, authenticate, isAdmin, upload.single('image'), async (req, res) => {
    const { catid, name, price, description } = req.body;
    const pid = req.params.pid;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    // Validate inputs
    const nameError = validateTextInput(name, 255, 'Product name');
    const descError = validateTextInput(description, 1000, 'Description');
    const priceError = validatePrice(price);
    if (nameError || descError || priceError || !catid) {
        return res.status(400).send(nameError || descError || priceError || 'Category ID is required');
    }

    const sanitizedName = sanitizeHtml(name);
    const sanitizedDesc = sanitizeHtml(description);

    if (imagePath) {
        // Validate image mime type
        if (!['image/jpeg', 'image/png', 'image/gif'].includes(req.file.mimetype)) {
            return res.status(400).send('Invalid image type. Only JPEG, PNG, or GIF allowed.');
        }

        sharp(req.file.path)
            .resize(200, 200)
            .toFile(`uploads/thumbnail-${req.file.filename}`, (err) => {
                if (err) {
                    console.error('Image resize error:', err);
                    return res.status(500).send('Internal Server Error');
                }
                const thumbnailPath = `/uploads/thumbnail-${req.file.filename}`;
                const sql = 'UPDATE products SET catid=?, name=?, price=?, description=?, image=?, thumbnail=? WHERE pid=?';
                db.query(sql, [catid, sanitizedName, price, sanitizedDesc, imagePath, thumbnailPath, pid], (err) => {
                    if (err) {
                        console.error('Update product error:', err);
                        return res.status(500).send('Internal Server Error');
                    }
                    res.send('Product updated');
                });
            });
    } else {
        const sql = 'UPDATE products SET catid=?, name=?, price=?, description=? WHERE pid=?';
        db.query(sql, [catid, sanitizedName, price, sanitizedDesc, pid], (err) => {
            if (err) {
                console.error('Update product error:', err);
                return res.status(500).send('Internal Server Error');
            }
            res.send('Product updated');
        });
    }
});

app.post('/add-category', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    const { name } = req.body;
    const nameError = validateTextInput(name, 255, 'Category name');
    if (nameError) return res.status(400).send(nameError);

    const sanitizedName = sanitizeHtml(name);
    db.query('INSERT INTO categories (name) VALUES (?)', [sanitizedName], (err) => {
        if (err) {
            console.error('Add category error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Category added');
    });
});

app.put('/update-category/:catid', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    const { name } = req.body;
    const catid = req.params.catid;
    const nameError = validateTextInput(name, 255, 'Category name');
    if (nameError) return res.status(400).send(nameError);

    const sanitizedName = sanitizeHtml(name);
    db.query('UPDATE categories SET name=? WHERE catid=?', [sanitizedName, catid], (err) => {
        if (err) {
            console.error('Update category error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Category updated');
    });
});

app.delete('/delete-product/:pid', validateCsrfToken, authenticate, isAdmin, (req, res) => {
    db.query('DELETE FROM products WHERE pid = ?', [req.params.pid], (err) => {
        if (err) {
            console.error('Delete product error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Product deleted');
    });
});

app.delete('/delete-category/:catid', validateCsrfToken, authenticate, isAdmin, (req, res) => {
    db.query('DELETE FROM categories WHERE catid = ?', [req.params.catid], (err) => {
        if (err) {
            console.error('Delete category error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Category deleted');
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).send('Internal Server Error');
});

http.createServer(app).listen(3443, '0.0.0.0', () => {
    console.log('HTTP Server running on port 3443');
});