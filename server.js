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
const fetch = require('node-fetch');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
dotenv.config();

const fs = require('fs');

const app = express();
const upload = multer({ dest: 'uploads/', limits: { fileSize: 10 * 1024 * 1024 } });

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

db.getConnection()
    .then(() => console.log('Database connected successfully'))
    .catch(err => {
        console.error('Database connection failed:', err);
        process.exit(1);
    });

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

// Middleware
app.use(cors({
    origin: [
        'https://ierg4210.koreacentral.cloudapp.azure.com',
        'https://20.249.188.8',
        'https://s32.ierg4210.ie.cuhk.edu.hk'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// Serve static files
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images'), {
    setHeaders: (res) => {
        res.set('Cache-Control', 'public, max-age=2592000'); // 30 days
    }
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
    setHeaders: (res) => {
        res.set('Cache-Control', 'public, max-age=2592000'); // 30 days
    }
}));

// Serve specific static files from root (e.g., HTML, CSS, JS)
app.get('*.html', (req, res) => {
    const filePath = path.join(__dirname, req.path);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).send('Not Found');
    }
});
app.get('*.css', (req, res) => {
    const filePath = path.join(__dirname, req.path);
    if (fs.existsSync(filePath)) {
        res.set('Cache-Control', 'public, max-age=2592000'); // 30 days
        res.sendFile(filePath);
    } else {
        res.status(404).send('Not Found');
    }
});
app.get('*.js', (req, res) => {
    const filePath = path.join(__dirname, req.path);
    if (fs.existsSync(filePath) && !req.path.endsWith('/server.js')) {
        res.set('Cache-Control', 'public, max-age=2592000'); // 30 days
        res.sendFile(filePath);
    } else if (req.path.endsWith('/server.js')) {
        res.status(403).send('Access Denied');
    } else {
        res.status(404).send('Not Found');
    }
});

// CSRF Protection
const generateCsrfToken = () => crypto.randomBytes(16).toString('hex');
app.use((req, res, next) => {
    if (!req.cookies.csrfToken) {
        const token = generateCsrfToken();
        console.log('Setting csrfToken cookie for:', req.hostname);
        res.cookie('csrfToken', token, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict'
        });
    }
    next();
});

const validateCsrfToken = (req, res, next) => {
    const csrfToken = req.cookies.csrfToken;
    const bodyToken = req.body.csrfToken || req.headers['x-csrf-token'] || req.cookies.csrfToken;
    if (!csrfToken || !bodyToken || csrfToken !== bodyToken) {
        console.error('CSRF token validation failed:', { csrfToken, bodyToken });
        return res.status(403).json({ error: 'CSRF token validation failed' });
    }
    next();
};

// Authentication Middleware
const authenticate = async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            // Assign a temporary guest ID for non-logged-in users
            if (!req.cookies.guestId) {
                const guestId = crypto.randomBytes(16).toString('hex');
                res.cookie('guestId', guestId, { 
                    httpOnly: true, 
                    secure: true, 
                    sameSite: 'strict',
                    maxAge: 24 * 60 * 60 * 1000 // 1 day
                });
            }
            req.user = { email: 'Guest', is_admin: false };
            return next();
        }
        
        const [results] = await db.query('SELECT * FROM users WHERE auth_token = ?', [authToken]);
        if (!results.length) {
            req.user = { email: 'Guest', is_admin: false };
            return next();
        }
        
        req.user = results[0];
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};

const isAdmin = (req, res, next) => {
    if (!req.user || !req.user.is_admin) return res.status(403).json({ error: 'Admin access required' });
    next();
};

// Input Validation
const validateTextInput = (text, maxLength, fieldName) => {
    if (!text || typeof text !== 'string') return `${fieldName} is required`;
    if (text.length > maxLength) return `${fieldName} must be ${maxLength} characters or less`;
    if (!/^[a-zA-Z0-9\s\-,.?!@]+$/.test(text)) return `${fieldName} contains invalid characters`;
    return null;
};

const validateName = (name, fieldName) => {
    if (!name || typeof name !== 'string') return `${fieldName} is required`;
    if (name.length > 50) return `${fieldName} must be 50 characters or less`;
    if (!/^[a-zA-Z\s\-]+$/.test(name)) return `${fieldName} can only contain letters, spaces, or hyphens`;
    return null;
};

const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) return 'Invalid email format';
    return null;
};

const validatePassword = (password) => {
    if (!password || password.length < 8) return 'Password must be at least 8 characters';
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

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/product', (req, res) => {
    res.sendFile(path.join(__dirname, 'product.html'));
});

app.get('/admin', authenticate, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

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
        
        res.json({ email: escapeHtml(results[0].email), isAdmin: results[0].is_admin });
    } catch (err) {
        console.error('User fetch error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/categories', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM categories');
        res.json(results.map(row => ({ catid: row.catid, name: escapeHtml(row.name) })));
    } catch (err) {
        console.error('Categories error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/products', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 8;
        const offset = (page - 1) * limit;

        if (page < 1 || limit < 1) {
            return res.status(400).json({ error: 'Invalid page or limit' });
        }

        const [countResult] = await db.query('SELECT COUNT(*) as total FROM products');
        const total = countResult[0].total;
        const totalPages = Math.ceil(total / limit);

        const [results] = await db.query('SELECT * FROM products LIMIT ? OFFSET ?', [limit, offset]);

        setTimeout(() => {
            res.json({
                products: results.map(row => ({
                    pid: row.pid,
                    catid: row.catid,
                    name: escapeHtml(row.name),
                    price: row.price,
                    description: escapeHtml(row.description),
                    image: row.image,
                    thumbnail: row.thumbnail
                })),
                pagination: {
                    total,
                    page,
                    limit,
                    totalPages
                }
            });
        }, 1000);
    } catch (err) {
        console.error('Products error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/products/:catid', async (req, res) => {
    try {
        const catid = parseInt(req.params.catid);
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 8;
        const offset = (page - 1) * limit;

        if (isNaN(catid) || page < 1 || limit < 1) {
            return res.status(400).json({ error: 'Invalid category ID, page, or limit' });
        }

        const [countResult] = await db.query('SELECT COUNT(*) as total FROM products WHERE catid = ?', [catid]);
        const total = countResult[0].total;
        const totalPages = Math.ceil(total / limit);

        const [results] = await db.query('SELECT * FROM products WHERE catid = ? LIMIT ? OFFSET ?', [catid, limit, offset]);

        setTimeout(() => {
            res.json({
                products: results.map(row => ({
                    pid: row.pid,
                    catid: row.catid,
                    name: escapeHtml(row.name),
                    price: row.price,
                    description: escapeHtml(row.description),
                    image: row.image,
                    thumbnail: row.thumbnail
                })),
                pagination: {
                    total,
                    page,
                    limit,
                    totalPages
                }
            });
        }, 1000);
    } catch (err) {
        console.error('Products by catid error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
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
            image: product.image || '',
            thumbnail: product.thumbnail || ''
        });
    } catch (err) {
        console.error('Product error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/orders', authenticate, (req, res) => {
    if (!req.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'orders.html'));
});

app.get('/orders-data', authenticate, async (req, res) => {
    if (!req.user || !req.user.email || req.user.email === 'Guest') {
        return res.status(403).json({ error: 'Authentication required' });
    }
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const offset = (page - 1) * limit;
    try {
        const [orders] = await db.query(
            'SELECT orderID AS order_id, total_price, status, created_at, items FROM orders WHERE user_email = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
            [req.user.email, limit, offset]
        );
        const [totalResult] = await db.query(
            'SELECT COUNT(*) as total FROM orders WHERE user_email = ?',
            [req.user.email]
        );
        const totalOrders = totalResult[0].total;
        const totalPages = Math.ceil(totalOrders / limit);
        res.json({ orders, totalPages });
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

app.get('/admin-orders', authenticate, isAdmin, async (req, res) => {
    try {
        const [orders] = await db.query('SELECT * FROM orders ORDER BY created_at DESC');
        res.json(orders.map(order => ({
            order_id: order.orderID,
            email: escapeHtml(order.user_email || 'Guest'),
            total_amount: order.total_price,
            items: order.items,
            status: order.status,
            created_at: order.created_at
        })));
    } catch (err) {
        console.error('Error fetching admin orders:', err);
        res.status(500).json({ error: 'Error fetching orders' });
    }
});

app.post('/send-verification-code', validateCsrfToken, async (req, res) => {
    try {
        console.log('Raw request body:', req.body);
        const { email, firstName, lastName, password } = req.body;

        // Validate input
        const emailError = validateEmail(email);
        const firstNameError = validateName(firstName, 'First Name');
        const lastNameError = validateName(lastName, 'Last Name');
        const passwordError = validatePassword(password);
        if (emailError || firstNameError || lastNameError || passwordError) {
            return res.status(400).json({ error: emailError || firstNameError || lastNameError || passwordError });
        }

        // Check if email already exists
        const [existing] = await db.query('SELECT email FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Generate verification code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Insert verification code
        await db.query(
            'INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)',
            [email, code, expiresAt]
        );
        console.log('Verification code inserted for email:', email);

        // Send email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify Your Email - Dummy Shopping Website',
            text: `Your verification code is: ${code}. It expires in 10 minutes.`
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true });
    } catch (err) {
        console.error('Send verification code error:', err);
        res.status(500).json({ error: 'An error occurred while sending the verification code' });
    }
});

app.post('/verify-code', validateCsrfToken, async (req, res) => {
    try {
        const { email, code, firstName, lastName, password } = req.body;
        console.log('Verify code attempt:', { email, code });

        // Validate inputs
        const emailError = validateEmail(email);
        const firstNameError = validateName(firstName, 'First Name');
        const lastNameError = validateName(lastName, 'Last Name');
        const passwordError = validatePassword(password);
        if (emailError || firstNameError || lastNameError || passwordError) {
            return res.status(400).json({ error: emailError || firstNameError || lastNameError || passwordError });
        }

        // Check verification code
        const [codes] = await db.query(
            'SELECT * FROM verification_codes WHERE email = ? AND code = ? AND expires_at > NOW()',
            [email, code]
        );
        if (codes.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired verification code' });
        }

        // Check if email already exists
        const [existing] = await db.query('SELECT email FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Insert user
        const hashedPassword = await bcrypt.hash(password, 10);
        const authToken = crypto.randomBytes(32).toString('hex');
        const sanitizedEmail = escapeHtml(email);
        const sanitizedFirstName = escapeHtml(firstName);
        const sanitizedLastName = escapeHtml(lastName);

        await db.query(
            'INSERT INTO users (email, firstName, lastName, password, auth_token, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
            [sanitizedEmail, sanitizedFirstName, sanitizedLastName, hashedPassword, authToken, 0]
        );

        // Delete verification code
        await db.query('DELETE FROM verification_codes WHERE email = ?', [email]);

        console.log('Setting authToken cookie for:', req.hostname);
        res.cookie('authToken', authToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 2 * 24 * 60 * 60 * 1000,
            path: '/'
        });

        res.json({ 
            success: true,
            redirect: '/',
            email: sanitizedEmail
        });
    } catch (err) {
        console.error('Verify code error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/signup', validateCsrfToken, async (req, res) => {
    try {
        const { email, firstName, lastName, password } = req.body;
        console.log('Signup attempt:', { email, domain: req.hostname });

        const emailError = validateEmail(email);
        const firstNameError = validateName(firstName, 'First Name');
        const lastNameError = validateName(lastName, 'Last Name');
        const passwordError = validatePassword(password);
        if (emailError || firstNameError || lastNameError || passwordError) {
            return res.status(400).json({ error: emailError || firstNameError || lastNameError || passwordError });
        }

        const [existingUsers] = await db.query('SELECT email FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const authToken = crypto.randomBytes(32).toString('hex');
        const sanitizedEmail = escapeHtml(email);
        const sanitizedFirstName = escapeHtml(firstName);
        const sanitizedLastName = escapeHtml(lastName);

        await db.query(
            'INSERT INTO users (email, firstName, lastName, password, auth_token, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
            [sanitizedEmail, sanitizedFirstName, sanitizedLastName, hashedPassword, authToken, 0]
        );

        console.log('Setting authToken cookie for:', req.hostname);
        res.cookie('authToken', authToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 2 * 24 * 60 * 60 * 1000,
            path: '/'
        });

        res.json({ 
            success: true,
            redirect: '/',
            email: sanitizedEmail
        });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/login', validateCsrfToken, async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt:', { email, domain: req.hostname });
        
        const [users] = await db.query(
            'SELECT userid, email, password, is_admin FROM users WHERE email = ?', 
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const match = await bcrypt.compare(password, user.password);
        
        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const authToken = crypto.randomBytes(32).toString('hex');
        
        await db.query(
            'UPDATE users SET auth_token = ? WHERE userid = ?',
            [authToken, user.userid]
        );

        console.log('Setting authToken cookie for:', req.hostname);
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
            email: escapeHtml(user.email)
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/logout', validateCsrfToken, authenticate, async (req, res) => {
    try {
        if (req.user.userid) {
            await db.query('UPDATE users SET auth_token = NULL WHERE userid = ?', [req.user.userid]);
        }
        console.log('Clearing authToken cookie for:', req.hostname);
        res.clearCookie('authToken');
        res.clearCookie('guestId');
        
        const newCsrfToken = generateCsrfToken();
        console.log('Setting new csrfToken cookie for:', req.hostname);
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
            return res.status(400).json({ error: 'Invalid input: New password must be at least 8 characters' });
        }

        const match = await bcrypt.compare(currentPassword, req.user.password);
        if (!match) return res.status(401).json({ error: 'Current password incorrect' });
        
        const hash = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = ?, auth_token = NULL WHERE userid = ?', [hash, req.user.userid]);
        
        console.log('Clearing authToken and csrfToken cookies for:', req.hostname);
        res.clearCookie('authToken');
        res.clearCookie('csrfToken');
        res.clearCookie('guestId');
        res.json({ success: true, redirect: '/login' });
    } catch (err) {
        console.error('Password change error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/validate-order', validateCsrfToken, authenticate, async (req, res) => {
    try {
        console.log('Validate-order request body:', req.body);
        const { items } = req.body;
        if (!items || !Array.isArray(items)) {
            console.log('Invalid items detected');
            return res.status(400).json({ error: 'Invalid items' });
        }

        let totalPrice = 0;
        const orderItems = [];
        const currency = 'USD';
        const merchantEmail = 'testing6070@example.com';
        const salt = crypto.randomBytes(16).toString('hex');

        for (const item of items) {
            console.log('Processing item:', item);
            if (!item.pid || !Number.isInteger(item.quantity) || item.quantity <= 0) {
                console.log('Invalid item data:', item);
                return res.status(400).json({ error: 'Invalid item data' });
            }

            const [products] = await db.query('SELECT pid, price FROM products WHERE pid = ?', [item.pid]);
            console.log('Database query result for pid', item.pid, ':', products);
            if (products.length === 0) {
                console.log('Product not found:', item.pid);
                return res.status(400).json({ error: `Product ${item.pid} not found` });
            }

            const product = products[0];
            totalPrice += product.price * item.quantity;
            orderItems.push({
                pid: item.pid,
                quantity: item.quantity,
                price: product.price
            });
        }

        const dataToHash = [
            currency,
            merchantEmail,
            salt,
            ...orderItems.map(item => `${item.pid}:${item.quantity}:${item.price}`)
        ].join('|');
        const digest = crypto.createHash('sha256').update(dataToHash).digest('hex');
        console.log('Digest data:', dataToHash);
        console.log('Generated digest:', digest);

        const userEmail = req.user && req.user.email !== 'Guest' ? req.user.email : null;
        console.log('User email:', userEmail);
        const [result] = await db.query(
            'INSERT INTO orders (user_email, items, total_price, digest, salt, status) VALUES (?, ?, ?, ?, ?, ?)',
            [userEmail, JSON.stringify(orderItems), totalPrice, digest, salt, 'pending']
        );
        console.log('Order inserted, ID:', result.insertId);

        res.json({ orderID: result.insertId, digest });
    } catch (err) {
        console.error('Order validation error:', err);
        res.status(400).json({ error: err.message || 'Internal Server Error' });
    }
});

app.post('/paypal-webhook', async (req, res) => {
    try {
        console.log('PayPal webhook received:', req.body);

        const verificationUrl = 'https://www.sandbox.paypal.com/cgi-bin/webscr?cmd=_notify-validate';
        const verificationBody = `cmd=_notify-validate&${new URLSearchParams(req.body).toString()}`;
        const verificationResponse = await fetch(verificationUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: verificationBody
        });
        const verificationResult = await verificationResponse.text();

        if (verificationResult !== 'VERIFIED') {
            console.error('PayPal verification failed:', verificationResult);
            return res.status(400).send('Invalid PayPal notification');
        }

        const paypalTxnId = req.body.txn_id;
        const [existing] = await db.query('SELECT transaction_id FROM transactions WHERE paypal_txn_id = ?', [paypalTxnId]);
        if (existing.length > 0) {
            console.warn('Transaction already processed:', paypalTxnId);
            return res.status(200).send('OK');
        }

        const orderID = parseInt(req.body.invoice);
        const [orders] = await db.query('SELECT * FROM orders WHERE orderID = ?', [orderID]);
        if (orders.length === 0) {
            console.error('Order not found:', orderID);
            return res.status(400).send('Order not found');
        }

        const order = orders[0];
        const orderItems = typeof order.items === 'string' ? JSON.parse(order.items) : order.items;

        const currency = 'USD';
        const merchantEmail = 'testing6070@example.com';
        const salt = order.salt;
        const dataToHash = [
            currency,
            merchantEmail,
            salt,
            ...orderItems.map(item => `${item.pid}:${item.quantity}:${item.price}`)
        ].join('|');
        const regeneratedDigest = crypto.createHash('sha256').update(dataToHash).digest('hex');

        if (regeneratedDigest !== order.digest) {
            console.error('Digest mismatch:', regeneratedDigest, order.digest);
            return res.status(400).send('Digest validation failed');
        }

        await db.query(
            'INSERT INTO transactions (orderID, paypal_txn_id, payment_status, payment_amount, currency_code, payer_email, created_at, items) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [
                orderID,
                paypalTxnId,
                req.body.payment_status,
                parseFloat(req.body.mc_gross),
                req.body.mc_currency,
                req.body.payer_email,
                new Date(),
                JSON.stringify(orderItems)
            ]
        );

        const status = req.body.payment_status === 'Completed' ? 'completed' : 'failed';
        await db.query('UPDATE orders SET status = ? WHERE orderID = ?', [status, orderID]);

        res.status(200).send('OK');
    } catch (err) {
        console.error('Webhook error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/add-product', validateCsrfToken, authenticate, isAdmin, upload.single('image'), async (req, res) => {
    try {
        const { catid, name, price, description } = req.body;
        const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

        const nameError = validateTextInput(name, 255, 'Product name');
        const descError = validateTextInput(description, 1000, 'Description');
        const priceError = validatePrice(price);
        if (nameError || descError || priceError || !catid) {
            return res.status(400).json({ error: nameError || descError || priceError || 'Category ID is required' });
        }

        const sanitizedName = sanitizeHtml(name);
        const sanitizedDesc = sanitizeHtml(description);

        if (imagePath) {
            if (!['image/jpeg', 'image/png', 'image/gif'].includes(req.file.mimetype)) {
                return res.status(400).json({ error: 'Invalid image type. Only JPEG, PNG, or GIF allowed.' });
            }

            await sharp(req.file.path)
                .resize(200, 200)
                .jpeg({ quality: 80 })
                .toFile(`uploads/thumbnail-${req.file.filename}`);

            const thumbnailPath = `/uploads/thumbnail-${req.file.filename}`;
            await db.query(
                'INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES (?, ?, ?, ?, ?, ?)',
                [catid, sanitizedName, price, sanitizedDesc, imagePath, thumbnailPath]
            );
        } else {
            await db.query(
                'INSERT INTO products (catid, name, price, description) VALUES (?, ?, ?, ?)',
                [catid, sanitizedName, price, sanitizedDesc]
            );
        }

        res.json({ success: true, message: 'Product added' });
    } catch (err) {
        console.error('Add product error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/update-product/:pid', validateCsrfToken, authenticate, isAdmin, upload.single('image'), async (req, res) => {
    try {
        const { catid, name, price, description } = req.body;
        const pid = req.params.pid;
        const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

        const nameError = validateTextInput(name, 255, 'Product name');
        const descError = validateTextInput(description, 1000, 'Description');
        const priceError = validatePrice(price);
        if (nameError || descError || priceError || !catid) {
            return res.status(400).json({ error: nameError || descError || priceError || 'Category ID is required' });
        }

        const sanitizedName = sanitizeHtml(name);
        const sanitizedDesc = sanitizeHtml(description);

        if (imagePath) {
            if (!['image/jpeg', 'image/png', 'image/gif'].includes(req.file.mimetype)) {
                return res.status(400).json({ error: 'Invalid image type. Only JPEG, PNG, or GIF allowed.' });
            }

            await sharp(req.file.path)
                .resize(200, 200)
                .jpeg({ quality: 80 })
                .toFile(`uploads/thumbnail-${req.file.filename}`);

            const thumbnailPath = `/uploads/thumbnail-${req.file.filename}`;
            await db.query(
                'UPDATE products SET catid = ?, name = ?, price = ?, description = ?, image = ?, thumbnail = ? WHERE pid = ?',
                [catid, sanitizedName, price, sanitizedDesc, imagePath, thumbnailPath, pid]
            );
        } else {
            await db.query(
                'UPDATE products SET catid = ?, name = ?, price = ?, description = ? WHERE pid = ?',
                [catid, sanitizedName, price, sanitizedDesc, pid]
            );
        }

        res.json({ success: true, message: 'Product updated' });
    } catch (err) {
        console.error('Update product error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/add-category', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        const { name } = req.body;
        const nameError = validateTextInput(name, 255, 'Category name');
        if (nameError) return res.status(400).json({ error: nameError });

        const sanitizedName = sanitizeHtml(name);
        await db.query('INSERT INTO categories (name) VALUES (?)', [sanitizedName]);
        res.json({ success: true, message: 'Category added' });
    } catch (err) {
        console.error('Add category error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/update-category/:catid', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        const { name } = req.body;
        const catid = req.params.catid;
        const nameError = validateTextInput(name, 255, 'Category name');
        if (nameError) return res.status(400).json({ error: nameError });

        const sanitizedName = sanitizeHtml(name);
        await db.query('UPDATE categories SET name = ? WHERE catid = ?', [sanitizedName, catid]);
        res.json({ success: true, message: 'Category updated' });
    } catch (err) {
        console.error('Update category error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/delete-product/:pid', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        const pid = req.params.pid;
        await db.query('DELETE FROM products WHERE pid = ?', [pid]);
        res.json({ success: true, message: 'Product deleted' });
    } catch (err) {
        console.error('Delete product error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/delete-category/:catid', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        const catid = req.params.catid;
        await db.query('DELETE FROM categories WHERE catid = ?', [catid]);
        res.json({ success: true, message: 'Category deleted' });
    } catch (err) {
        console.error('Delete category error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Chat Routes
app.post('/send-message', validateCsrfToken, authenticate, async (req, res) => {
    try {
        const { message } = req.body;
        const messageError = validateTextInput(message, 1000, 'Message');
        if (messageError) return res.status(400).json({ error: messageError });

        const sanitizedMessage = sanitizeHtml(message);
        const userEmail = req.user.email !== 'Guest' ? req.user.email : null;
        await db.query(
            'INSERT INTO messages (user_email, message, status, seen) VALUES (?, ?, ?, ?)',
            [userEmail, sanitizedMessage, 'pending', 0]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Send message error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/user-messages', authenticate, async (req, res) => {
    try {
        const userEmail = req.user.email !== 'Guest' ? req.user.email : null;
        if (!userEmail) {
            return res.json([]);
        }

        const [results] = await db.query(
            'SELECT message_id, user_email, message, response, status, created_at, responded_at, seen FROM messages WHERE user_email = ? ORDER BY created_at ASC',
            [userEmail]
        );
        res.json(results.map(row => ({
            message_id: row.message_id,
            user_email: escapeHtml(row.user_email || 'Guest'),
            message: escapeHtml(row.message),
            response: row.response ? escapeHtml(row.response) : null,
            status: row.status,
            created_at: row.created_at,
            responded_at: row.responded_at,
            seen: row.seen
        })));
    } catch (err) {
        console.error('User messages fetch error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/admin-messages', authenticate, isAdmin, async (req, res) => {
    try {
        const filter = req.query.filter === 'responded' ? 'responded' : 'pending';
        const [results] = await db.query(
            'SELECT message_id, user_email, message, response, status, created_at, responded_at, seen FROM messages WHERE status = ? ORDER BY created_at DESC',
            [filter]
        );
        res.json(results.map(row => ({
            message_id: row.message_id,
            user_email: escapeHtml(row.user_email || 'Guest'),
            message: escapeHtml(row.message),
            response: row.response ? escapeHtml(row.response) : null,
            status: row.status,
            created_at: row.created_at,
            responded_at: row.responded_at,
            seen: row.seen
        })));
    } catch (err) {
        console.error('Admin messages fetch error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/respond-message', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        console.log('Respond-message request:', req.body);
        const { messageId, response } = req.body;
        if (!messageId || !response) {
            console.error('Missing messageId or response');
            return res.status(400).json({ error: 'Message ID and response are required' });
        }

        const messageError = validateTextInput(response, 1000, 'Response');
        if (messageError) {
            console.error('Response validation error:', messageError);
            return res.status(400).json({ error: messageError });
        }

        const sanitizedResponse = sanitizeHtml(response);
        const [messages] = await db.query('SELECT * FROM messages WHERE message_id = ?', [messageId]);
        if (messages.length === 0) {
            console.error('Message not found:', messageId);
            return res.status(404).json({ error: 'Message not found' });
        }

        await db.query(
            'UPDATE messages SET response = ?, status = ?, responded_at = NOW(), seen = 0 WHERE message_id = ?',
            [sanitizedResponse, 'responded', messageId]
        );
        console.log('Message responded:', { messageId, response: sanitizedResponse });
        res.json({ success: true });
    } catch (err) {
        console.error('Respond message error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/mark-messages-seen', validateCsrfToken, authenticate, async (req, res) => {
    try {
        const userEmail = req.user.email !== 'Guest' ? req.user.email : null;
        if (!userEmail) return res.status(403).json({ error: 'Authentication required' });

        await db.query(
            'UPDATE messages SET seen = 1 WHERE user_email = ? AND response IS NOT NULL',
            [userEmail]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Mark messages seen error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/bulk-delete-messages', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        const { messageIds } = req.body;
        if (!Array.isArray(messageIds) || messageIds.length === 0) {
            return res.status(400).json({ error: 'Invalid message IDs' });
        }

        const placeholders = messageIds.map(() => '?').join(',');
        await db.query(
            `DELETE FROM messages WHERE message_id IN (${placeholders})`,
            messageIds
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Bulk delete messages error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/bulk-resolve-messages', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        const { messageIds } = req.body;
        if (!Array.isArray(messageIds) || messageIds.length === 0) {
            return res.status(400).json({ error: 'Invalid message IDs' });
        }

        const placeholders = messageIds.map(() => '?').join(',');
        await db.query(
            `UPDATE messages SET status = ?, responded_at = NOW(), seen = 0 WHERE message_id IN (${placeholders})`,
            ['responded', ...messageIds]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Bulk resolve messages error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

http.createServer(app).listen(3443, '0.0.0.0', () => {
    console.log('HTTP Server running on port 3443');
});