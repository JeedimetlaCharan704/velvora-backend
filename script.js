const API_URL = 'https://velvora-backend.onrender.com/api';
let products = [];
let cart = JSON.parse(localStorage.getItem('velvoraCart')) || [];
let wishlist = JSON.parse(localStorage.getItem('velvoraWishlist')) || [];
let currentSlide = 0;
let lastScroll = 0;

async function loadProducts() {
    try {
        const response = await fetch(`${API_URL}/products`);
        const data = await response.json();
        console.log('API Response:', data);
        products = data.products || data;
        console.log('Loaded products:', products);
    } catch (error) {
        console.error('Failed to load products:', error);
        products = [];
    }
}

async function init() {
    await loadProducts();
    renderProducts();
    renderNewArrivals();
    updateCartCount();
    updateWishlistCount();
    initSlider();
    initScrollEffects();
    initAnimations();
    updateUserUI();
    initTestimonials();
    
    window.addEventListener('resize', () => {
        initTestimonials();
    });
}

function updateUserUI() {
    const user = JSON.parse(localStorage.getItem('velvoraUser'));
    const userIcon = document.getElementById('userIcon');
    const profileIcon = document.getElementById('profileIcon');
    
    if (user) {
        if (userIcon) userIcon.style.display = 'none';
        if (profileIcon) profileIcon.style.display = 'flex';
    } else {
        if (userIcon) userIcon.style.display = 'flex';
        if (profileIcon) profileIcon.style.display = 'none';
    }
}

function renderProducts(filter = 'all', searchTerm = '', limit = 4) {
    const grid = document.getElementById('productGrid');
    let filtered = products;

    if (filter !== 'all') {
        if (filter === 'sale') {
            filtered = products.filter(p => p.tag === 'sale');
        } else if (filter === 'new') {
            filtered = products.filter(p => p.tag === 'new');
        } else {
            filtered = products.filter(p => p.category === filter);
        }
    }

    if (searchTerm) {
        filtered = filtered.filter(p => p.name.toLowerCase().includes(searchTerm.toLowerCase()));
    }

    const productsToShow = filtered.slice(0, limit);
    grid.innerHTML = productsToShow.map(product => createProductCard(product)).join('');
    
    // Store all filtered products for toggle
    grid.dataset.allProducts = JSON.stringify(filtered);
}

function createProductCard(product) {
    const productId = product._id || product.id;
    const isInWishlist = wishlist.includes(productId);
    const stars = '★'.repeat(product.rating || 0) + '☆'.repeat(5 - (product.rating || 0));
    const placeholderImg = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAwIiBoZWlnaHQ9IjQwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iNDAwIiBoZWlnaHQ9IjQwMCIgZmlsbD0iI2YxZjVmOSIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBkb21pbmFudC1iYXNlbGluZT0ibWlkZGxlIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmaWxsPSIjOWNhM2FmIiBmb250LWZhbWlseT0iYXJpYWwiIGZvbnQtc2l6ZT0iMjAiPkltYWdlPC90ZXh0Pjwvc3ZnPg==';
    
    return `
        <div class="product-card" data-category="${product.category}">
            ${product.tag ? `<span class="product-tag ${product.tag}">${product.tag.toUpperCase()}</span>` : ''}
            <span class="wishlist-btn ${isInWishlist ? 'active' : ''}" onclick="toggleWishlistItem('${productId}', event)">
                <i class="${isInWishlist ? 'fas' : 'far'} fa-heart"></i>
            </span>
            <div class="product-image" onclick="openProductModal('${productId}')">
                <img src="${product.image}" alt="${product.name}" onerror="this.src='${placeholderImg}'">
                <div class="product-overlay">
                    <button class="quick-view-btn" onclick="openProductModal('${productId}')">
                        <i class="fas fa-eye"></i> Quick View
                    </button>
                </div>
            </div>
            <div class="product-info">
                <h3 onclick="openProductModal('${productId}')">${product.name}</h3>
                <div class="product-rating">${stars}</div>
                <div class="product-price">
                    <span class="price">$${(product.price || 0).toFixed(2)}</span>
                    ${product.originalPrice ? `<span class="original-price">$${product.originalPrice.toFixed(2)}</span>` : ''}
                </div>
                <button class="add-to-cart-btn" onclick="addToCart('${productId}')">
                    <i class="fas fa-shopping-bag"></i> Add to Bag
                </button>
            </div>
        </div>
    `;
}

function renderNewArrivals() {
    const grid = document.getElementById('newArrivalsGrid');
    if (!grid) return;
    console.log('All products:', products);
    const newProducts = products.filter(p => p.tag && p.tag.toLowerCase() === 'new').slice(0, 4);
    console.log('New products:', newProducts);
    if (newProducts.length === 0) {
        grid.innerHTML = '<p class="no-products">No new arrivals yet</p>';
    } else {
        grid.innerHTML = newProducts.map(product => createProductCard(product)).join('');
    }
}

function addToCart(productId, quantity = 1) {
    const product = products.find(p => (p._id || p.id) == productId);
    const existingItem = cart.find(item => (item._id || item.id) == productId);

    if (existingItem) {
        existingItem.quantity += quantity;
    } else {
        cart.push({ ...product, quantity, id: productId });
    }

    saveCart();
    updateCartCount();
    showNotification(`${product.name} added to bag!`);
}

function addToCartFromModal(productId) {
    const product = products.find(p => (p._id || p.id) == productId);
    const categorySizes = getModalSizes(product);
    const hasSizes = categorySizes.length > 0;
    
    if (hasSizes && !selectedModalSize) {
        const errorEl = document.querySelector('.modal-size-error');
        if (errorEl) {
            errorEl.style.display = 'block';
            document.querySelector('.modal-size-options').classList.add('shake');
            setTimeout(() => {
                document.querySelector('.modal-size-options').classList.remove('shake');
            }, 500);
        }
        return;
    }
    
    const quantity = parseInt(document.getElementById('modalQuantityValue').textContent);
    
    const existingItem = cart.find(item => (item._id || item.id) == productId);
    if (existingItem) {
        existingItem.quantity += quantity;
    } else {
        cart.push({ ...product, quantity, id: productId });
    }
    
    saveCart();
    updateCartCount();
    closeModal();
    showNotification(`${product.name} added to bag!`);
}

function removeFromCart(productId) {
    cart = cart.filter(item => (item._id || item.id) != productId);
    saveCart();
    updateCartCount();
    renderCartItems();
}

function updateQuantity(productId, change) {
    const item = cart.find(item => (item._id || item.id) == productId);
    if (item) {
        item.quantity += change;
        if (item.quantity <= 0) {
            removeFromCart(productId);
        } else {
            saveCart();
            updateCartCount();
            renderCartItems();
        }
    }
}

function saveCart() {
    localStorage.setItem('velvoraCart', JSON.stringify(cart));
}

function updateCartCount() {
    const count = cart.reduce((sum, item) => sum + item.quantity, 0);
    document.getElementById('cartCount').textContent = count;
    document.getElementById('cartCount').style.display = count > 0 ? 'block' : 'none';
}

function renderCartItems() {
    const container = document.getElementById('cartItems');
    const totalEl = document.getElementById('cartTotal');
    
    if (cart.length === 0) {
        container.innerHTML = '<p class="cart-empty"><i class="fas fa-shopping-bag"></i> Your bag is empty</p>';
        totalEl.textContent = '$0.00';
        return;
    }

    const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    totalEl.textContent = `$${total.toFixed(2)}`;

    container.innerHTML = cart.map(item => `
        <div class="cart-item">
            <img src="${item.image}" alt="${item.name}">
            <div class="cart-item-info">
                <h4>${item.name}</h4>
                <p class="cart-item-price">$${item.price.toFixed(2)}</p>
                <div class="quantity-controls">
                    <button onclick="updateQuantity(${item.id}, -1)">-</button>
                    <span>${item.quantity}</span>
                    <button onclick="updateQuantity(${item.id}, 1)">+</button>
                </div>
            </div>
            <span class="cart-item-remove" onclick="removeFromCart(${item.id})">
                <i class="fas fa-times"></i>
            </span>
        </div>
    `).join('');
}

function toggleCart() {
    const sidebar = document.getElementById('cartSidebar');
    sidebar.classList.toggle('active');
    document.body.style.overflow = sidebar.classList.contains('active') ? 'hidden' : '';
    renderCartItems();
}

function toggleWishlistItem(productId, event) {
    event.stopPropagation();
    const index = wishlist.indexOf(productId);
    const product = products.find(p => (p._id || p.id) == productId);

    if (index > -1) {
        wishlist.splice(index, 1);
        showNotification(`${product.name} removed from wishlist`);
    } else {
        wishlist.push(productId);
        showNotification(`${product.name} added to wishlist`);
    }

    localStorage.setItem('velvoraWishlist', JSON.stringify(wishlist));
    updateWishlistCount();
    renderProducts(document.querySelector('.filter-btn.active')?.textContent.toLowerCase() || 'all');
    renderNewArrivals();
}

function updateWishlistCount() {
    const count = wishlist.length;
    document.getElementById('wishlistCount').textContent = count;
    document.getElementById('wishlistCount').style.display = count > 0 ? 'block' : 'none';
}

function renderWishlistItems() {
    const container = document.getElementById('wishlistItems');
    
    if (wishlist.length === 0) {
        container.innerHTML = '<p class="wishlist-empty"><i class="far fa-heart"></i> Your wishlist is empty</p>';
        return;
    }

    const wishlistProducts = products.filter(p => {
        const pid = p._id || p.id;
        return wishlist.includes(pid);
    });
    container.innerHTML = wishlistProducts.map(product => {
        const productId = product._id || product.id;
        return `
        <div class="wishlist-item">
            <img src="${product.image}" alt="${product.name}">
            <div class="wishlist-item-info">
                <h4>${product.name}</h4>
                <p>$${product.price.toFixed(2)}</p>
                <button onclick="addToCart('${productId}'); toggleWishlistItem('${productId}', event)">
                    <i class="fas fa-shopping-bag"></i> Add to Bag
                </button>
            </div>
            <span onclick="toggleWishlistItem('${productId}', event)">
                <i class="fas fa-times"></i>
            </span>
        </div>
    `}).join('');
}

function toggleWishlist() {
    const sidebar = document.getElementById('wishlistSidebar');
    sidebar.classList.toggle('active');
    document.body.style.overflow = sidebar.classList.contains('active') ? 'hidden' : '';
    renderWishlistItems();
}

function openProductModal(productId) {
    const product = products.find(p => (p._id || p.id) == productId);
    const modal = document.getElementById('productModal');
    const modalBody = document.getElementById('modalBody');
    const stars = '★'.repeat(product.rating || 0) + '☆'.repeat(5 - (product.rating || 0));
    const categorySizes = getModalSizes(product);
    const hasSizes = categorySizes.length > 0;
    
    selectedModalSize = null;
    modalQty = 1;
    
    const sizeSection = hasSizes ? `
        <div class="modal-size-section">
            <span class="modal-size-label">Select Size</span>
            <div class="modal-size-options">
                ${categorySizes.map(size => `<span class="modal-size-option" data-size="${size}" onclick="selectModalSize('${size}')">${size}</span>`).join('')}
            </div>
            <p class="modal-size-error">Please select a size</p>
        </div>
    ` : `
        <div class="modal-size-section">
            <span class="modal-size-label">Size</span>
            <div class="modal-free-size">
                <span class="free-size-badge">Free Size</span>
            </div>
        </div>
    `;

    modalBody.innerHTML = `
        <div class="modal-image">
            <img src="${product.image}" alt="${product.name}">
        </div>
        <div class="modal-details">
            <span class="modal-category">${product.category}</span>
            <h2>${product.name}</h2>
            <div class="modal-rating">${stars}</div>
            <p class="modal-price">
                <span class="current-price">$${(product.price || 0).toFixed(2)}</span>
                ${product.originalPrice ? `<span class="original-price">$${product.originalPrice.toFixed(2)}</span>` : ''}
            </p>
            ${sizeSection}
            <p class="modal-description">Experience unparalleled luxury with this exquisite piece. Crafted from the finest materials with meticulous attention to detail.</p>
            <div class="modal-quantity">
                <span>Quantity:</span>
                <div class="quantity-selector">
                    <button onclick="modalQuantity(-1)">-</button>
                    <span id="modalQuantityValue">1</span>
                    <button onclick="modalQuantity(1)">+</button>
                </div>
            </div>
            <div class="modal-actions">
                <button class="add-to-cart-modal" onclick="addToCartFromModal('${productId}')">
                    <i class="fas fa-shopping-bag"></i> Add to Bag
                </button>
                <button class="wishlist-modal" onclick="toggleWishlistItem('${productId}', event)">
                    <i class="far fa-heart"></i>
                </button>
            </div>
        </div>
    `;

    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
}

let modalQty = 1;
let selectedModalSize = null;

const sizeByCategory = {
    women: ['XS', 'S', 'M', 'L', 'XL'],
    men: ['XS', 'S', 'M', 'L', 'XL', 'XXL'],
    kids: ['XS', 'S', 'M', 'L', 'XL'],
    shoes: ['6', '7', '8', '9', '10', '11'],
    accessories: []
};

function selectModalSize(size) {
    selectedModalSize = size;
    document.querySelectorAll('.modal-size-option').forEach(opt => opt.classList.remove('selected'));
    document.querySelector(`.modal-size-option[data-size="${size}"]`).classList.add('selected');
}

function getModalSizes(product) {
    const category = product.category;
    const name = product.name.toLowerCase();
    
    if (name.includes('sneaker') || name.includes('boot') || name.includes('shoe') || name.includes('heel') || name.includes('sandal')) {
        return ['6', '7', '8', '9', '10', '11'];
    }
    
    if (category === 'accessories') {
        return [];
    }
    
    return sizeByCategory[category] || [];
}

function modalQuantity(change) {
    modalQty = Math.max(1, modalQty + change);
    document.getElementById('modalQuantityValue').textContent = modalQty;
}

function closeModal() {
    document.getElementById('productModal').classList.remove('active');
    document.body.style.overflow = '';
    modalQty = 1;
}

function filterProducts(category) {
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    renderProducts(category);
}

function filterCategory(category) {
    renderProducts(category);
    scrollToSection('products');
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
}

function searchProducts(term) {
    const resultsContainer = document.getElementById('searchResults');
    
    if (term.length < 2) {
        resultsContainer.style.display = 'none';
        return;
    }

    const results = products.filter(p => p.name.toLowerCase().includes(term.toLowerCase())).slice(0, 5);
    
    if (results.length === 0) {
        resultsContainer.innerHTML = '<p class="no-results">No products found</p>';
    } else {
        resultsContainer.innerHTML = results.map(p => `
            <div class="search-result-item" onclick="openProductModal(${p.id})">
                <img src="${p.image}" alt="${p.name}">
                <div>
                    <h4>${p.name}</h4>
                    <p>$${p.price.toFixed(2)}</p>
                </div>
            </div>
        `).join('');
    }
    
    resultsContainer.style.display = 'block';
}

document.addEventListener('click', (e) => {
    if (!e.target.closest('.search-container')) {
        document.getElementById('searchResults').style.display = 'none';
    }
});

function toggleProducts() {
    const btn = document.getElementById('viewAllBtn');
    const grid = document.getElementById('productGrid');
    const isExpanded = btn.getAttribute('data-expanded') === 'true';
    const allProducts = JSON.parse(grid.dataset.allProducts || '[]');
    
    if (isExpanded) {
        // Show only 4 products
        const productsToShow = allProducts.slice(0, 4);
        grid.innerHTML = productsToShow.map(product => createProductCard(product)).join('');
        btn.textContent = 'View All Products';
        btn.setAttribute('data-expanded', 'false');
    } else {
        // Show all products
        grid.innerHTML = allProducts.map(product => createProductCard(product)).join('');
        btn.textContent = 'Show Less';
        btn.setAttribute('data-expanded', 'true');
    }
}

let testimonialIndex = 0;
let testimonialInitialized = false;

function initTestimonials() {
    const cards = document.querySelectorAll('.testimonial-card');
    
    if (window.innerWidth <= 768) {
        cards.forEach((card, index) => {
            card.style.display = index === 0 ? 'block' : 'none';
            card.classList.toggle('active', index === 0);
        });
        testimonialInitialized = true;
    } else {
        cards.forEach(card => {
            card.style.display = '';
            card.classList.remove('active');
        });
        testimonialIndex = 0;
    }
}

function initSlider() {
    const slides = document.querySelectorAll('.slide');
    
    function showSlide(index) {
        slides.forEach(slide => slide.classList.remove('active'));
        slides[index].classList.add('active');
    }

    window.nextSlide = function() {
        currentSlide = (currentSlide + 1) % slides.length;
        showSlide(currentSlide);
    }

    window.prevSlide = function() {
        currentSlide = (currentSlide - 1 + slides.length) % slides.length;
        showSlide(currentSlide);
    }

    setInterval(nextSlide, 6000);
}

function prevTestimonial() {
    const cards = document.querySelectorAll('.testimonial-card');
    if (cards.length === 0) return;
    
    cards[testimonialIndex].style.display = 'none';
    cards[testimonialIndex].classList.remove('active');
    testimonialIndex = (testimonialIndex - 1 + cards.length) % cards.length;
    cards[testimonialIndex].style.display = 'block';
    cards[testimonialIndex].classList.add('active');
}

function nextTestimonial() {
    const cards = document.querySelectorAll('.testimonial-card');
    if (cards.length === 0) return;
    
    cards[testimonialIndex].style.display = 'none';
    cards[testimonialIndex].classList.remove('active');
    testimonialIndex = (testimonialIndex + 1) % cards.length;
    cards[testimonialIndex].style.display = 'block';
    cards[testimonialIndex].classList.add('active');
}

function initScrollEffects() {
    const header = document.querySelector('.header');

    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;

        if (currentScroll > 100) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }

        if (currentScroll <= 0) {
            header.classList.remove('hide');
            return;
        }

        if (currentScroll > lastScroll) {
            header.classList.add('hide');
        } else {
            header.classList.remove('hide');
        }

        lastScroll = currentScroll;
    });
}

function initAnimations() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('show');
            }
        });
    }, { threshold: 0.1 });

    document.querySelectorAll('section').forEach(sec => {
        sec.classList.add('hidden');
        observer.observe(sec);
    });

    const statsObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateStats();
                statsObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    document.querySelectorAll('.stats-section').forEach(el => {
        statsObserver.observe(el);
    });
}

function animateStats() {
    document.querySelectorAll('.stat-number').forEach(stat => {
        const target = parseInt(stat.getAttribute('data-count'));
        const duration = 2000;
        const step = target / (duration / 16);
        let current = 0;

        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                stat.textContent = target.toLocaleString();
                clearInterval(timer);
            } else {
                stat.textContent = Math.floor(current).toLocaleString();
            }
        }, 16);
    });
}

function scrollToSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        const headerHeight = document.querySelector('.header').offsetHeight;
        const sectionTop = section.offsetTop - headerHeight - 20;
        window.scrollTo({ top: sectionTop, behavior: 'smooth' });
    }
}

function scrollToTop() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function setActive(element) {
    document.querySelectorAll('.nav a').forEach(link => link.classList.remove('active'));
    element.classList.add('active');
}

function toggleMenu() {
    document.querySelector('.nav').classList.toggle('active');
    document.querySelector('.menu-overlay').classList.toggle('active');
}

function showNotification(message) {
    const notification = document.getElementById('notification');
    const text = document.getElementById('notificationText');
    text.textContent = message;
    notification.classList.add('show');
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

function subscribeNewsletter(e) {
    e.preventDefault();
    const email = e.target.querySelector('input').value;
    showNotification(`Thank you! 10% off code: WELCOME${email.substring(0, 3).toUpperCase()}`);
    e.target.reset();
}

function subscribeFooter(e) {
    e.preventDefault();
    const email = e.target.querySelector('input').value;
    showNotification(`Welcome to Velvora Circle, ${email.split('@')[0]}!`);
    e.target.reset();
}

function checkout() {
    if (cart.length === 0) {
        showNotification('Your bag is empty!');
        return;
    }
    showNotification('Proceeding to checkout...');
}

function goToCheckout() {
    if (cart.length === 0) {
        showNotification('Your bag is empty!');
        return;
    }
    window.location.href = 'checkout.html';
}

document.getElementById('productModal')?.addEventListener('click', (e) => {
    if (e.target === document.getElementById('productModal')) {
        closeModal();
    }
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
        document.getElementById('cartSidebar')?.classList.remove('active');
        document.getElementById('wishlistSidebar')?.classList.remove('active');
        document.querySelector('.nav')?.classList.remove('active');
    }
});

document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
    });
});

init();
