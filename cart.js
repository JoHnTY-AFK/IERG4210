document.addEventListener('click', (event) => {
    if (event.target.classList.contains('add-to-cart')) {
        const productId = parseInt(event.target.getAttribute('data-pid'));
        fetch(`/product/${productId}`, { credentials: 'include' })
            .then(response => {
                if (!response.ok) throw new Error('Product fetch failed');
                return response.json();
            })
            .then(product => {
                let cart = JSON.parse(localStorage.getItem('cart')) || [];
                const existingProduct = cart.find(item => item.pid === productId);

                if (existingProduct) {
                    existingProduct.quantity += 1;
                } else {
                    cart.push({ pid: productId, name: product.name, price: product.price, quantity: 1 });
                }

                localStorage.setItem('cart', JSON.stringify(cart));
                updateCartUI();
            })
            .catch(err => console.error('Cart add error:', err));
    }
});

// Function to sanitize payment form fields
function sanitizePaymentField(value) {
    return value.replace(/[^a-zA-Z0-9\s\-,.]/g, '');
}

function updateCartUI() {
    const cart = JSON.parse(localStorage.getItem('cart')) || [];
    const cartItems = document.querySelector('.cart-items');
    const cartButton = document.getElementById('cart-button');
    cartItems.innerHTML = '';

    let totalAmount = 0;

    // Create PayPal form
    const paypalForm = document.createElement('form');
    paypalForm.id = 'paypal-form';
    paypalForm.method = 'POST';
    paypalForm.action = 'https://www.sandbox.paypal.com/cgi-bin/webscr';

    // PayPal required hidden fields
    const returnUrl = `${window.location.origin}/?payment=success`;
    const notifyUrl = `${window.location.origin}/paypal-webhook`;
    paypalForm.innerHTML = `
        <input type="hidden" name="cmd" value="_cart">
        <input type="hidden" name="upload" value="1">
        <input type="hidden" name="business" value="testing6070@example.com">
        <input type="hidden" name="charset" value="utf-8">
        <input type="hidden" name="currency_code" value="USD">
        <input type="hidden" name="invoice" id="invoice">
        <input type="hidden" name="custom" id="custom">
        <input type="hidden" name="return" value="${returnUrl}">
        <input type="hidden" name="notify_url" value="${notifyUrl}">
    `;

    // Create Alipay form
    const alipayForm = document.createElement('form');
    alipayForm.id = 'alipay-form';
    alipayForm.method = 'POST';
    alipayForm.action = '/alipay-create-payment';

    cart.forEach((item, index) => {
        totalAmount += item.price * item.quantity;
        const itemIndex = index + 1;
        const cartItem = document.createElement('li');
        cartItem.innerHTML = DOMPurify.sanitize(`
            ${item.name} - <input type="number" value="${item.quantity}" min="0" data-pid="${item.pid}"> x $${item.price}
        `);
        const sanitizedName = sanitizePaymentField(item.name);
        paypalForm.innerHTML += `
            <input type="hidden" name="item_name_${itemIndex}" value="${sanitizedName}">
            <input type="hidden" name="item_number_${itemIndex}" value="${item.pid}">
            <input type="hidden" name="amount_${itemIndex}" value="${item.price}">
            <input type="hidden" name="quantity_${itemIndex}" value="${item.quantity}">
        `;
        alipayForm.innerHTML += `
            <input type="hidden" name="item_name_${itemIndex}" value="${sanitizedName}">
            <input type="hidden" name="item_number_${itemIndex}" value="${item.pid}">
            <input type="hidden" name="amount_${itemIndex}" value="${item.price}">
            <input type="hidden" name="quantity_${itemIndex}" value="${item.quantity}">
        `;
        cartItems.appendChild(cartItem);
    });

    const totalElement = document.createElement('li');
    totalElement.className = 'total';
    totalElement.textContent = `Total: $${totalAmount.toFixed(2)}`;
    cartItems.appendChild(totalElement);

    // Payment method selector with radio buttons
    const paymentSelector = document.createElement('div');
    paymentSelector.className = 'payment-selector';
    paymentSelector.innerHTML = DOMPurify.sanitize(`
        <h4>Select Payment Method</h4>
        <label class="payment-option">
            <input type="radio" name="payment-method" value="paypal" checked>
            <span class="payment-icon paypal-icon"></span>
            <span class="payment-label">PayPal</span>
            <span class="payment-desc">Secure payments with PayPal</span>
        </label>
        <label class="payment-option">
            <input type="radio" name="payment-method" value="alipay">
            <span class="payment-icon alipay-icon"></span>
            <span class="payment-label">Alipay</span>
            <span class="payment-desc">Fast and secure with Alipay</span>
        </label>
    `);

    const checkoutButton = document.createElement('button');
    checkoutButton.className = 'checkout';
    checkoutButton.textContent = 'Checkout';
    cartItems.appendChild(paymentSelector);
    cartItems.appendChild(paypalForm);
    cartItems.appendChild(alipayForm);
    cartItems.appendChild(checkoutButton);

    const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
    cartButton.textContent = `Cart (${totalItems})`;
}

document.addEventListener('change', (event) => {
    if (event.target.tagName === 'INPUT' && event.target.type === 'number') {
        const pid = parseInt(event.target.getAttribute('data-pid'));
        const newQuantity = parseInt(event.target.value);
        let cart = JSON.parse(localStorage.getItem('cart')) || [];

        if (newQuantity <= 0) {
            cart = cart.filter(item => item.pid !== pid);
        } else {
            const product = cart.find(item => item.pid === pid);
            if (product) product.quantity = newQuantity;
        }

        localStorage.setItem('cart', JSON.stringify(cart));
        updateCartUI();
    }
});

document.addEventListener('click', (event) => {
    if (event.target.classList.contains('checkout')) {
        console.log('Checkout button clicked');
        event.preventDefault();
        const cart = JSON.parse(localStorage.getItem('cart')) || [];
        if (cart.length === 0) {
            alert('Cart is empty');
            return;
        }

        const paymentMethod = document.querySelector('input[name="payment-method"]:checked').value;
        console.log('Selected payment method:', paymentMethod);

        // Validate quantities
        const items = cart.map(item => ({
            pid: parseInt(item.pid),
            quantity: item.quantity
        }));

        for (const item of items) {
            if (!Number.isInteger(item.quantity) || item.quantity <= 0) {
                alert('Invalid quantity for product ID ' + item.pid);
                return;
            }
        }

        // Fetch CSRF token
        fetch('/csrf-token', { credentials: 'include' })
            .then(response => {
                if (!response.ok) throw new Error('CSRF token fetch failed');
                return response.json();
            })
            .then(data => {
                const csrfToken = data.csrfToken;
                return fetch('/validate-order', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ items, csrfToken, payment_provider: paymentMethod }),
                    credentials: 'include'
                });
            })
            .then(response => {
                if (!response.ok) throw new Error('Order validation failed');
                return response.json();
            })
            .then(data => {
                if (paymentMethod === 'paypal') {
                    const paypalForm = document.getElementById('paypal-form');
                    document.getElementById('invoice').value = data.orderID;
                    document.getElementById('custom').value = data.digest;

                    // Log PayPal form data before submission
                    const formData = new FormData(paypalForm);
                    const formDataObject = {};
                    for (let [key, value] of formData.entries()) {
                        formDataObject[key] = value;
                    }
                    console.log('PayPal form data (before submission):', formDataObject);

                    // Validate that cart items are present
                    if (!formDataObject['item_name_1']) {
                        console.error('No cart items found in form data');
                        alert('Error: Cart items are missing. Please try adding items again.');
                        return;
                    }

                    // Submit the PayPal form
                    paypalForm.submit();
                } else if (paymentMethod === 'alipay') {
                    const alipayForm = document.getElementById('alipay-form');
                    alipayForm.innerHTML += `
                        <input type="hidden" name="orderID" value="${data.orderID}">
                        <input type="hidden" name="digest" value="${data.digest}">
                    `;
                    // Submit the Alipay form to backend for payment creation
                    alipayForm.submit();
                }

                // Clear cart and update UI after submission
                localStorage.removeItem('cart');
                updateCartUI();
            })
            .catch(err => {
                console.error('Checkout error:', err);
                alert('Checkout failed: ' + err.message);
            });
    }
});

document.addEventListener('DOMContentLoaded', () => {
    // Check for payment success query parameter
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('payment') === 'success') {
        alert('Payment successful! Thank you for your purchase.');
        history.replaceState({}, '', '/');
    }
});

const cartButton = document.getElementById('cart-button');
const shoppingCart = document.getElementById('shopping-cart');
let hideTimeout;

// Show cart on mouseenter
cartButton.addEventListener('mouseenter', () => {
    clearTimeout(hideTimeout);
    shoppingCart.classList.add('visible');
});

shoppingCart.addEventListener('mouseenter', () => {
    clearTimeout(hideTimeout);
    shoppingCart.classList.add('visible');
});

// Hide cart after a delay on mouseleave
cartButton.addEventListener('mouseleave', () => {
    hideTimeout = setTimeout(() => {
        shoppingCart.classList.remove('visible');
    }, 300);
});

shoppingCart.addEventListener('mouseleave', () => {
    hideTimeout = setTimeout(() => {
        shoppingCart.classList.remove('visible');
    }, 300);
});

// Close cart immediately when clicking the close button
document.querySelector('.close-cart').addEventListener('click', () => {
    clearTimeout(hideTimeout);
    shoppingCart.classList.remove('visible');
});

updateCartUI();