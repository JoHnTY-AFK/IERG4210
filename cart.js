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
    cart.forEach(item => {
        totalAmount += item.price * item.quantity;
        const cartItem = document.createElement('li');
        // Use DOMPurify for safe HTML
        cartItem.innerHTML = DOMPurify.sanitize(`
            ${item.name} - <input type="number" value="${item.quantity}" min="0" data-pid="${item.pid}"> x $${item.price}
        `);
        cartItems.appendChild(cartItem);
    });

    const totalElement = document.createElement('li');
    totalElement.className = 'total';
    totalElement.textContent = `Total: $${totalAmount.toFixed(2)}`;
    cartItems.appendChild(totalElement);

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

const cartButton = document.getElementById('cart-button');
const shoppingCart = document.getElementById('shopping-cart');

cartButton.addEventListener('mouseenter', () => shoppingCart.classList.add('visible'));
cartButton.addEventListener('mouseleave', () => shoppingCart.classList.remove('visible'));
shoppingCart.addEventListener('mouseenter', () => shoppingCart.classList.add('visible'));
shoppingCart.addEventListener('mouseleave', () => shoppingCart.classList.remove('visible'));
document.querySelector('.close-cart').addEventListener('click', () => shoppingCart.classList.remove('visible'));

updateCartUI();