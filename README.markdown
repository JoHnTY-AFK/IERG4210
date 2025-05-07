# Dummy Shopping Website

## Overview
The Dummy Shopping Website is a fully functional e-commerce platform built for educational purposes. It allows users to browse products, filter by categories, add items to a shopping cart, place orders via PayPal, view order history, and manage their accounts. Administrators can manage products, categories, and view all orders. The application is hosted on an Azure Virtual Machine (VM) with an Azure MySQL database, using Nginx as a reverse proxy to a Node.js backend. The frontend is built with HTML, CSS, and JavaScript, incorporating security features like CSRF protection, input sanitization, and HTTPS.

### Key Features
- **User Functionality**:
  - Browse products and filter by category.
  - View detailed product information.
  - Add products to a shopping cart and checkout via PayPal Sandbox.
  - View the last five orders (authenticated users only).
  - Log in/out with email and password.
- **Admin Functionality**:
  - Add, edit, or delete products and categories.
  - Change admin password.
  - View all orders across all users.
- **Security**:
  - CSRF token protection for all POST/PUT/DELETE requests.
  - Passwords hashed with bcrypt.
  - Input sanitization using `DOMPurify` (frontend) and `sanitize-html` (backend).
  - HTTPS enforced via Nginx with Let’s Encrypt certificates.
  - Secure cookies with `HttpOnly`, `Secure`, and `SameSite=Strict`.

### Hosted URLs
- **Primary**: [https://ierg4210.koreacentral.cloudapp.azure.com/](https://ierg4210.koreacentral.cloudapp.azure.com/)
- **Secondary**: [https://s32.ierg4210.ie.cuhk.edu.hk/](https://s32.ierg4210.ie.cuhk.edu.hk/)
- **IP**: 20.249.188.8

### Source Code
- **GitHub Repository**: [https://github.com/JoHnTY-AFK/IERG4210.git](https://github.com/JoHnTY-AFK/IERG4210.git)
- **Local Path on Azure VM**: `/home/azureuser/ierg4210/`

---

## Technology Stack
- **Frontend**:
  - HTML, CSS, JavaScript
  - `DOMPurify` for sanitizing HTML output
- **Backend**:
  - Node.js with Express.js
  - Middleware: CORS, body-parser, cookie-parser
  - Libraries: `mysql2`, `multer` (file uploads), `sharp` (image resizing), `bcrypt`, `sanitize-html`, `node-fetch`, `dotenv`
- **Database**:
  - Azure MySQL (`shopping_db`) with SSL
- **Server**:
  - Nginx (reverse proxy and static file serving)
  - Node.js running on port 3443
- **Hosting**:
  - Azure Virtual Machine (Ubuntu)
  - SSL: Let’s Encrypt for domains, self-signed for IP
- **Version Control**:
  - Git (GitHub)

---

## Project Structure
The project is organized as follows:

```
/home/azureuser/ierg4210/
├── images/                    # Static product images
├── public/                    # Publicly accessible files
│   ├── admin.html             # Admin panel page
│   └── styles/                # CSS styles
│       ├── admin.css          # Admin panel styles
│       └── main.css           # General styles
├── cart.js                    # Shopping cart functionality
├── DigiCertGlobalRootCA.crt.pem # SSL certificate for MySQL
├── hashPasswords.js           # Utility script for password hashing
├── index.html                 # Homepage
├── login.html                 # Login page
├── nginx-old.conf             # Backup Nginx configuration
├── nginx.conf                 # Active Nginx configuration
├── orders.html                # User orders page
├── package-lock.json          # Node.js dependencies lock file
├── package.json               # Node.js project metadata
├── product.html               # Product details page
├── server.js                  # Node.js backend server
├── setup.sql                  # MySQL database schema and initial data
└── structure.txt              # Project structure documentation
```

### File Descriptions
1. **index.html**:
   - **Purpose**: Homepage displaying products and categories.
   - **Features**:
     - Navigation bar (Home, Categories, About, Admin, My Orders, Logout).
     - Category dropdown to filter products.
     - Product list with thumbnails, names, prices, and "Add to Cart" buttons.
     - Shopping cart UI (visible on hover).
     - Breadcrumb navigation.
   - **JavaScript**:
     - Fetches CSRF token (`/csrf-token`) for logout.
     - Checks user status (`/user`) to update navigation links.
     - Loads categories (`/categories`) and products (`/products` or `/products/:catid`).
     - Updates URL and breadcrumb on category change.
   - **Dependencies**: `cart.js`, `DOMPurify`, `/styles/main.css`.

2. **login.html**:
   - **Purpose**: User authentication page.
   - **Features**:
     - Form for email and password.
     - Client-side validation (email format, password length 8–50 characters).
     - Submits to `/login` with CSRF token.
     - Redirects to `/` (users) or `/admin` (admins).
   - **JavaScript**:
     - Fetches CSRF token (`/csrf-token`).
     - Handles form submission and error display.
   - **Dependencies**: `DOMPurify`, `/styles/main.css`.

3. **product.html**:
   - **Purpose**: Displays detailed product information.
   - **Features**:
     - Shows product name, price, description, and image based on `pid` query parameter.
     - Includes "Add to Cart" button and navigation bar.
     - Fallback image (`/images/fallback.jpg`) if image fails to load.
   - **JavaScript**:
     - Fetches CSRF token (`/csrf-token`) and user status (`/user`).
     - Loads product data (`/product/:pid`).
   - **Dependencies**: `cart.js`, `DOMPurify`, `/styles/main.css`.

4. **orders.html**:
   - **Purpose**: Displays the last five orders for a logged-in user.
   - **Features**:
     - Lists orders with Order ID, Total Amount, Items, Status, and Date.
     - Requires authentication; redirects guests to `/login`.
     - Includes navigation and cart UI.
   - **JavaScript**:
     - Fetches CSRF token (`/csrf-token`) and user status (`/user`).
     - Loads order data (`/orders-data`).
   - **Dependencies**: `cart.js`, `DOMPurify`, `/styles/main.css`.

5. **admin.html**:
   - **Purpose**: Admin panel for managing products, categories, and passwords.
   - **Features**:
     - Forms to add/edit products (category, name, price, description, image).
     - Forms to add/edit categories (name).
     - Password change form.
     - Lists products, categories, and all orders with view/edit/delete options.
     - Requires admin authentication.
   - **JavaScript**:
     - Fetches CSRF token (`/csrf-token`) and validates admin status (`/user`).
     - Loads categories (`/categories`), products (`/products`), and orders (`/admin-orders`).
     - Handles form submissions and deletions.
   - **Dependencies**: `/styles/admin.css`, `DOMPurify`.

6. **cart.js**:
   - **Purpose**: Manages shopping cart functionality across all pages.
   - **Features**:
     - Adds products to cart (`/product/:pid`) and stores in `localStorage`.
     - Updates cart UI with items, quantities, total price, and PayPal checkout form.
     - Allows quantity changes (removes items if quantity is 0).
     - Validates orders (`/validate-order`) and submits to PayPal Sandbox.
     - Clears cart on successful checkout.
   - **Dependencies**: `DOMPurify`.

7. **server.js**:
   - **Purpose**: Node.js backend server handling API requests and database interactions.
   - **Features**:
     - **Middleware**: CORS, body parsing, cookies, static file serving.
     - **Security**: CSRF tokens, bcrypt password hashing, input sanitization, secure cookies.
     - **Routes**:
       - Static pages: `/`, `/login`, `/product`, `/orders`, `/admin`.
       - APIs: `/csrf-token`, `/user`, `/categories`, `/products`, `/product/:pid`, `/orders`, `/orders-data`, `/admin-orders`.
       - Authentication: `/login`, `/logout`, `/change-password`.
       - Order handling: `/validate-order`, `/paypal-webhook`.
       - Admin: `/add-product`, `/update-product/:pid`, `/add-category`, `/update-category/:catid`, `/delete-product/:pid`, `/delete-category/:catid`.
     - **Image Handling**: Uses `multer` for uploads and `sharp` for thumbnails.
   - **Dependencies**: `express`, `mysql2`, `multer`, `sharp`, `cors`, `cookie-parser`, `crypto`, `bcrypt`, `sanitize-html`, `node-fetch`, `dotenv`.

8. **setup.sql**:
   - **Purpose**: Initializes the MySQL database schema and populates initial data.
   - **Features**:
     - Creates `shopping_db` database.
     - Defines tables: `categories`, `products`, `users`, `orders`, `transactions`.
     - Inserts initial data: 3 categories, 12 products, 3 users (admin, user, PayPal test account).
   - **Tables**:
     - `categories`: ID, name.
     - `products`: ID, category, name, price, description, image, thumbnail.
     - `users`: ID, email, password, admin status, auth token.
     - `orders`: ID, user email, items, total price, digest, salt, status, timestamp.
     - `transactions`: PayPal transaction details linked to orders.

9. **nginx.conf**:
   - **Purpose**: Configures Nginx as a reverse proxy and static file server.
   - **Features**:
     - Listens on ports 80 (redirects to HTTPS) and 443 (SSL).
     - Supports multiple domains/IPs with Let’s Encrypt and self-signed certificates.
     - Serves static files (`/images/`, `/uploads/`) with caching.
     - Proxies dynamic requests to Node.js (`localhost:3443`).
     - Adds security headers (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy).

10. **DigiCertGlobalRootCA.crt.pem**:
    - **Purpose**: SSL certificate for secure MySQL connections.

11. **hashPasswords.js**:
    - **Purpose**: Utility script for generating hashed passwords (not detailed in provided files).

---

## How It Works
### User Flow
1. **Browsing**:
   - Users visit `index.html` to browse products and filter by category.
   - Clicking a product redirects to `product.html?pid=<id>` for details.
2. **Cart & Checkout**:
   - Users add products to the cart via `cart.js`, which stores items in `localStorage`.
   - The cart UI shows items, quantities, and a PayPal checkout form.
   - Orders are validated (`/validate-order`) and submitted to PayPal Sandbox.
   - PayPal IPN notifications (`/paypal-webhook`) update order status.
3. **Authentication**:
   - Users log in via `login.html` (`/login`), receiving an `authToken` cookie.
   - The frontend checks user status (`/user`) to update navigation (e.g., show "My Orders").
   - Logout (`/logout`) clears the `authToken`.
4. **Order History**:
   - Logged-in users view their last five orders on `orders.html` (`/orders-data`).
5. **Admin Management**:
   - Admins access `admin.html` to manage products, categories, and passwords.
   - All orders are viewable via `/admin-orders`.

### Backend-Frontend Interaction
- **Frontend**: Uses `fetch` to call backend APIs, with CSRF tokens for security.
- **Backend**: `server.js` handles requests, queries the MySQL database, and returns JSON or redirects.
- **Database**: Stores all data, with `setup.sql` defining the schema.
- **Nginx**: Serves static files and proxies API requests to Node.js.

### Security Measures
- **CSRF Protection**: Tokens generated by `/csrf-token` and validated in `server.js`.
- **Sanitization**: `DOMPurify` (frontend) and `sanitize-html` (backend) prevent XSS.
- **Authentication**: `authToken` cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
- **HTTPS**: Enforced by Nginx with valid SSL certificates.

---

## Setup Instructions
### Prerequisites
- **Azure Account**: For VM and MySQL database.
- **Node.js**: Version 16 or higher.
- **MySQL**: Azure MySQL or local instance.
- **Nginx**: Installed on the VM.
- **Git**: For cloning the repository.
- **Certbot**: For Let’s Encrypt SSL certificates.
- **PM2**: For running Node.js in production (optional).

### Local Setup
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/JoHnTY-AFK/IERG4210.git
   cd IERG4210
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Set Up Environment Variables**:
   - Create a `.env` file in the project root:
     ```env
     DB_HOST=<your_mysql_host>
     DB_USER=<your_mysql_user>
     DB_PASSWORD=<your_mysql_password>
     DB_NAME=shopping_db
     DB_SSL_CA=/path/to/DigiCertGlobalRootCA.crt.pem
     PAYPAL_CLIENT_ID=<your_paypal_client_id>
     PAYPAL_CLIENT_SECRET=<your_paypal_client_secret>
     PAYPAL_SANDBOX_URL=https://api-m.sandbox.paypal.com
     ```
   - Replace placeholders with your Azure MySQL and PayPal Sandbox credentials.

4. **Initialize the Database**:
   - Connect to your MySQL server:
     ```bash
     mysql -h <DB_HOST> -u <DB_USER> -p
     ```
   - Run the schema and initial data:
     ```sql
     source setup.sql;
     ```

5. **Start the Backend**:
   ```bash
   node server.js
   ```
   - The server runs on `http://localhost:3443`.

6. **Set Up Nginx (Optional for Local)**:
   - Install Nginx and copy `nginx.conf` to `/etc/nginx/nginx.conf`.
   - Update the `server_name` to `localhost` or your local domain.
   - Restart Nginx:
     ```bash
     sudo systemctl restart nginx
     ```

7. **Access the Website**:
   - Open `http://localhost` in a browser.
   - Use test credentials:
     - User: `user@example.com` / `password123`
     - Admin: `admin@example.com` / `admin123`
     - PayPal Test: `testing6070@example.com` / `password123`

### Azure Deployment
1. **Set Up Azure VM**:
   - Create an Ubuntu VM in Azure (e.g., Standard_D2s_v3).
   - Assign public IP: `20.249.188.8`.
   - Open ports 80 and 443 in the Azure Network Security Group.

2. **Install Dependencies on VM**:
   - SSH into the VM:
     ```bash
     ssh -i ~/.ssh/azure-key azureuser@20.249.188.8
     ```
   - Install Node.js, Nginx, Git, and Certbot:
     ```bash
     sudo apt update
     sudo apt install -y nodejs npm nginx git certbot python3-certbot-nginx
     sudo npm install -g pm2
     ```

3. **Clone Repository**:
   ```bash
   cd ~/
   git clone https://github.com/JoHnTY-AFK/IERG4210.git
   cd ierg4210
   npm install
   ```

4. **Configure MySQL**:
   - Upload `DigiCertGlobalRootCA.crt.pem` to `/home/azureuser/ierg4210/`:
     ```bash
     scp -i ~/.ssh/azure-key DigiCertGlobalRootCA.crt.pem azureuser@20.249.188.8:~/ierg4210/
     ```
   - Set up Azure MySQL database and update `.env` with credentials.
   - Run `setup.sql` on the MySQL server.

5. **Configure Nginx**:
   - Copy `nginx.conf` to `/etc/nginx/nginx.conf`:
     ```bash
     sudo cp nginx.conf /etc/nginx/nginx.conf
     ```
   - Obtain Let’s Encrypt certificates:
     ```bash
     sudo certbot --nginx -d ierg4210.koreacentral.cloudapp.azure.com -d s32.ierg4210.ie.cuhk.edu.hk
     ```
   - Update `nginx.conf` with certificate paths if needed.
   - Test and restart Nginx:
     ```bash
     sudo nginx -t
     sudo systemctl restart nginx
     ```

6. **Run the Backend**:
   - Start the Node.js server with PM2:
     ```bash
     pm2 start server.js --name server
     pm2 save
     ```
   - Ensure it runs on port 3443.

7. **Test Deployment**:
   - Access both URLs:
     - [https://ierg4210.koreacentral.cloudapp.azure.com/](https://ierg4210.koreacentral.cloudapp.azure.com/)
     - [https://s32.ierg4210.ie.cuhk.edu.hk/](https://s32.ierg4210.ie.cuhk.edu.hk/)
   - Log in with test credentials and verify functionality.

---

## Troubleshooting
### Common Issues
1. **Automatic Logout on `ierg4210.koreacentral.cloudapp.azure.com`**:
   - **Symptom**: Users are logged out after a period.
   - **Cause**: Possible cookie expiration or `authToken` mismatch.
   - **Fix**:
     - Check `authToken` cookie in browser (Developer Tools → Application → Cookies).
     - Verify `auth_token` in `users` table matches the cookie.
     - Add logging to `/user` endpoint in `server.js`:
       ```javascript
       console.log('User endpoint called with authToken:', authToken);
       ```
     - Ensure `sameSite: 'strict'` and `secure: true` in cookie settings.

2. **Login Fails on `s32.ierg4210.ie.cuhk.edu.hk`**:
   - **Symptom**: No errors, but the logged-in state isn’t reflected.
   - **Cause**: Possible cookie domain mismatch or SSL certificate issue.
   - **Fix**:
     - Check `/login` response in Developer Tools (Network tab).
     - Set cookie `domain` in `server.js`:
       ```javascript
       res.cookie('authToken', authToken, { domain: '.ierg4210.ie.cuhk.edu.hk', ... });
       ```
     - Verify SSL certificate:
       ```bash
       openssl s_client -connect s32.ierg4210.ie.cuhk.edu.hk:443
       ```

3. **Database Connection Errors**:
   - **Cause**: Incorrect `.env` credentials or missing SSL certificate.
   - **Fix**:
     - Verify `.env` settings and `DigiCertGlobalRootCA.crt.pem` path.
     - Test MySQL connection:
       ```bash
       mysql -h <DB_HOST> -u <DB_USER> -p --ssl-ca=DigiCertGlobalRootCA.crt.pem
       ```

4. **Nginx Errors**:
   - **Cause**: Misconfigured `nginx.conf` or invalid certificates.
   - **Fix**:
     - Check Nginx logs:
       ```bash
       sudo cat /var/log/nginx/error.log
       ```
     - Validate configuration:
       ```bash
       sudo nginx -t
       ```

### Debugging Tips
- **Frontend**: Use browser Developer Tools (Console and Network tabs) to inspect API responses and errors.
- **Backend**: Add `console.log` statements in `server.js` and check logs with `pm2 logs server`.
- **Database**: Query tables directly to verify data integrity:
  ```sql
  SELECT * FROM users;
  SELECT * FROM orders;
  ```

---

## Future Improvements
- **UI/UX**: Upgrade to a modern frontend framework (e.g., React) for better interactivity.
- **Security**: Implement rate limiting and CAPTCHA for login attempts.
- **Features**:
  - Add password recovery via email.
  - Support product search and sorting.
- **Performance**: Add database indexing and Redis for caching.
- **Monitoring**: Integrate error logging (e.g., Sentry) and performance monitoring.

---

## Contact
For issues or contributions, open a pull request or issue on the [GitHub repository](https://github.com/JoHnTY-AFK/IERG4210.git).