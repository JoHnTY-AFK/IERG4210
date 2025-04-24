document.addEventListener('click', (event) => {
    if (event.target.classList.contains('add-to-cart')) {
        const productId = event.target.getAttribute('data-pid');
        fetch(`https://ierg4210.koreacentral.cloudapp.azure.com/product/${productId}`)
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

function updateCartUI() {
    const cart = JSON.parse(localStorage.getItem('cart')) || [];
    const cartItems = document.querySelector('.cart-items');
    const cartButton = document.getElementById('cart-button');
    cartItems.innerHTML = '';

    let totalAmount = 0;
    const form = document.createElement('form');
    form.id = 'paypal-form';
    form.method = 'POST';
    form.action = 'https://www.sandbox.paypal.com/cgi-bin/webscr'; // Sandbox URL

    // PayPal required hidden fields
    form.innerHTML = `
        <input type="hidden" name="cmd" value="_cart">
        <input type="hidden" name="upload" value="1">
        <input type="hidden" name="business" value="testing6070@example.com">
        <input type="hidden" name="charset" value="utf-8">
        <input type="hidden" name="currency_code" value="USD">
        <input type="hidden" name="invoice" id="invoice">
        <input type="hidden" name="custom" id="custom">
        <input type="hidden" name="return" value="https://ierg4210.koreacentral.cloudapp.azure.com/">
        <input type="hidden" name="notify_url" value="https://ierg4210.koreacentral.cloudapp.azure.com/paypal-webhook">
    `;

    cart.forEach((item, index) => {
        totalAmount += item.price * item.quantity;
        const itemIndex = index + 1; // PayPal indices start at 1
        const cartItem = document.createElement('li');
        cartItem.innerHTML = DOMPurify.sanitize(`
            ${item.name} - <input type="number" value="${item.quantity}" min="0" data-pid="${item.pid}"> x $${item.price}
        `);
        form.innerHTML += `
            <input type="hidden" name="item_name_${itemIndex}" value="${item.name}">
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

    const checkoutButton = document.createElement('button');
    checkoutButton.className = 'checkout';
    checkoutButton.textContent = 'Checkout';
    cartItems.appendChild(form);
    form.appendChild(checkoutButton);

    const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
    cartButton.textContent = `Cart (${totalItems})`;
}

document.addEventListener('change', (event) => {
    if (event.target.tagName === 'INPUT' && event.target.type === 'number') {
        const pid = event.target.getAttribute('data-pid');
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
    if (event.target.className === 'checkout') {
        event.preventDefault();
        const cart = JSON.parse(localStorage.getItem('cart')) || [];
        if (cart.length === 0) {
            alert('Cart is empty');
            return;
        }

        const items = cart.map(item => ({ pid: item.pid, quantity: item.quantity }));
        fetch('https://ierg4210.koreacentral.cloudapp.azure.com/validate-order', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items }),
            credentials: 'include'
        })
            .then(response => {
                if (!response.ok) throw new Error('Order validation failed');
                return response.json();
            })
            .then(data => {
                // Set PayPal form fields
                document.getElementById('invoice').value = data.orderID;
                document.getElementById('custom').value = data.digest;

                // Clear cart
                localStorage.removeItem('cart');
                updateCartUI();

                // Programmatically submit the form to PayPal
                document.getElementById('paypal-form').submit();
            })
            .catch(err => {
                console.error('Checkout error:', err);
                alert('Checkout failed: ' + err.message);
            });
    }
});

const cartButton = document.getElementById('cart-button');
const shoppingCart = document.getElementById('shopping-cart');

cartButton.addEventListener('mouseenter', () => shoppingCart.classList.add('visible'));
cartButton.addEventListener('mouseleave', () => shoppingCart.classList.remove('visible'));
shoppingCart.addEventListener('mouseenter', () => shoppingCart.classList.add('visible'));
shoppingCart.addEventListener('mouseleave', () => shoppingCart.classList.remove('visible'));
document.querySelector('.close-cart').addEventListener('click', () => shoppingCart.classList.remove('visible'));

updateCartUI();