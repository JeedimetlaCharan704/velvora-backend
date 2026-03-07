// API Configuration
// Change this to your production URL when deploying
const API_URL = localStorage.getItem('apiUrl') || 'https://velvora-backend.onrender.com/api';
let authToken = localStorage.getItem('velvoraAdminToken');
let allProducts = [];
let allOrders = [];
let cropper = null;
let currentImageCallback = null;

// Show API URL configuration modal
function showApiConfigModal() {
    const savedUrl = localStorage.getItem('apiUrl') || '';
    const modal = document.createElement('div');
    modal.id = 'apiConfigModal';
    modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML = `
        <div style="background:white;padding:40px;border-radius:20px;max-width:500px;width:90%;text-align:center;">
            <h2 style="color:#c9a86c;margin-bottom:20px;">Configure API URL</h2>
            <p style="color:#666;margin-bottom:20px;">The backend API is not accessible. Please enter your backend URL:</p>
            <input type="text" id="apiUrlInput" placeholder="https://your-backend.onrender.com/api" 
                style="width:100%;padding:15px;border:2px solid #ddd;border-radius:10px;margin-bottom:20px;font-size:14px;"
                value="${savedUrl}">
            <div style="display:flex;gap:10px;justify-content:center;">
                <button onclick="saveApiUrl()" style="background:#c9a86c;color:white;border:none;padding:15px 30px;border-radius:10px;cursor:pointer;font-size:16px;">Save & Reload</button>
                <button onclick="location.reload()" style="background:#ddd;color:#333;border:none;padding:15px 30px;border-radius:10px;cursor:pointer;font-size:16px;">Cancel</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function saveApiUrl() {
    const url = document.getElementById('apiUrlInput').value.trim();
    if (url) {
        localStorage.setItem('apiUrl', url);
        location.reload();
    }
}

// Test API connection
async function testApiConnection() {
    try {
        const response = await fetch(`${API_URL}/health`);
        const data = await response.json();
        console.log('API Connected:', data);
        return true;
    } catch (e) {
        console.error('API Connection Failed:', e);
        showApiConfigModal();
        return false;
    }
}

// Helper function for API calls
async function apiCall(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        ...(authToken && { Authorization: `Bearer ${authToken}` }),
        ...options.headers
    };

    try {
        const url = `${API_URL}${endpoint}?t=${Date.now()}`;
        
        const response = await fetch(url, {
            ...options,
            headers
        });

        if (response.status === 401) {
            logoutAdmin();
            throw new Error('Session expired');
        }

        const text = await response.text();
        
        if (!text.trim()) {
            return { success: true };
        }
        
        // Check if response is HTML (error page)
        if (text.trim().startsWith('<!DOCTYPE') || text.trim().startsWith('<html')) {
            throw new Error(`API returned error page. Check your API URL (${API_URL})`);
        }
        
        const data = JSON.parse(text);
        if (!response.ok) {
            throw new Error(data.message || `Request failed with status ${response.status}`);
        }
        return data;
    } catch (e) {
        console.error('API Error:', e.message);
        if (e.message.includes('returned error page') || e.message.includes('Failed to fetch')) {
            showApiConfigModal();
        }
        throw e;
    }
}

// Initialize Admin
async function initAdmin() {
    console.log('Initializing Admin with API URL:', API_URL);
    
    // Test API connection first
    const connected = await testApiConnection();
    if (!connected) return;
    
    // Clear any old demo token and force fresh login
    if (authToken === 'demo-token') {
        localStorage.removeItem('velvoraAdminToken');
        localStorage.removeItem('velvoraAdminUser');
        authToken = null;
    }
    
    const user = JSON.parse(localStorage.getItem('velvoraAdminUser'));
    
    // Check if user is logged in with valid admin token
    if (!authToken || !user || user.role !== 'admin') {
        // Try to setup and auto-login with default admin credentials
        try {
            // First try to create admin if not exists
            await fetch(`${API_URL}/auth/setup`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            // Then try to login
            const response = await fetch(`${API_URL}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: 'admin@velvora.com', password: 'admin123' })
            });
            
            if (response.ok) {
                const data = await response.json();
                localStorage.setItem('velvoraAdminUser', JSON.stringify(data.user));
                localStorage.setItem('velvoraAdminToken', data.token);
                authToken = data.token;
            } else {
                alert('Please login to admin panel');
                window.location.href = 'login.html';
            }
        } catch (e) {
            console.error('Connection error:', e);
            showApiConfigModal();
            return;
        }
    }

    try {
        await Promise.all([
            loadProducts(),
            loadOrders(),
            loadStats()
        ]);
    } catch (e) {
        console.error('Error loading data:', e);
    }
    
    // Initialize charts after data is loaded
    if (typeof initCharts === 'function') {
        initCharts();
    }
}

// Load Products from API
async function loadProducts() {
    try {
        const data = await apiCall('/products/admin/all');
        allProducts = data;
        renderProducts();
        document.getElementById('totalProducts').textContent = data.length;
    } catch (error) {
        console.error('Error loading products:', error);
        alert('Failed to load products. Please refresh the page.');
    }
}

// Load Orders from API
async function loadOrders() {
    try {
        const data = await apiCall('/orders');
        allOrders = data.orders;
        renderOrders();
        renderAllOrders();
        
        // Update dashboard stats
        animateValue('totalOrders', 0, data.total || 0);
        
        const totalRevenue = data.orders.reduce((sum, o) => sum + (o.total || 0), 0);
        animateValue('totalRevenue', 0, totalRevenue);
        
        const avgOrderValue = data.total > 0 ? (totalRevenue / data.total) : 0;
        document.getElementById('avgOrderValue').textContent = '$' + avgOrderValue.toFixed(2);
    } catch (error) {
        console.error('Error loading orders:', error);
    }
}

// Load Stats
async function loadStats() {
    try {
        const stats = await apiCall('/orders/stats/summary');
        
        animateValue('totalOrders', 0, stats.totalOrders || 0);
        animateValue('totalRevenue', 0, stats.totalRevenue || 0);
        
        const avgOrderValue = stats.totalOrders > 0 
            ? (stats.totalRevenue / stats.totalOrders) 
            : 0;
        document.getElementById('avgOrderValue').textContent = '$' + avgOrderValue.toFixed(2);
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Load Customers
async function loadCustomers() {
    try {
        const users = await apiCall('/users');
        renderCustomers(users);
        document.getElementById('totalCustomers').textContent = users.length;
    } catch (error) {
        console.error('Error loading customers:', error);
    }
}

// Render Customers
function renderCustomers(users) {
    const grid = document.getElementById('customersGrid');
    if (!grid) return;
    
    if (users.length === 0) {
        grid.innerHTML = '<p class="no-data">No customers yet</p>';
        return;
    }
    
    grid.innerHTML = users.map(user => `
        <div class="customer-card">
            <div class="customer-avatar">
                <i class="fas fa-user"></i>
            </div>
            <div class="customer-info">
                <h4>${user.name}</h4>
                <p>${user.email}</p>
                <p>${user.phone || 'No phone'}</p>
                <span class="customer-date">Joined: ${new Date(user.createdAt).toLocaleDateString()}</span>
            </div>
        </div>
    `).join('');
}

// Render Recent Orders (Dashboard)
function renderOrders() {
    const tbody = document.getElementById('ordersTableBody');
    const container = tbody?.parentElement;
    
    if (allOrders.length === 0) {
        if (tbody) tbody.innerHTML = '<tr><td colspan="6">No orders yet</td></tr>';
        return;
    }
    
    const recentOrders = allOrders.slice(0, 5);
    
    // Desktop table
    if (tbody) {
        tbody.innerHTML = recentOrders.map(order => `
            <tr>
                <td>${order.orderId}</td>
                <td>${order.customerName || order.customer?.name || 'N/A'}</td>
                <td>${new Date(order.createdAt).toLocaleDateString()}</td>
                <td>$${order.total?.toFixed(2) || '0.00'}</td>
                <td><span class="status-badge ${(order.status || 'pending').toLowerCase()}">${order.status || 'Pending'}</span></td>
                <td><button class="action-btn" onclick="viewOrder('${order._id}')"><i class="fas fa-eye"></i></button></td>
            </tr>
        `).join('');
    }
    
    // Mobile cards
    if (container) {
        let mobileCards = container.querySelector('.mobile-cards');
        if (!mobileCards) {
            mobileCards = document.createElement('div');
            mobileCards.className = 'mobile-cards';
            container.appendChild(mobileCards);
        }
        
        mobileCards.innerHTML = recentOrders.map(order => `
            <div class="recent-order-card">
                <div class="recent-order-info">
                    <strong>${order.orderId}</strong>
                    <span>${order.customerName || order.customer?.name || 'N/A'}</span>
                </div>
                <div class="recent-order-info">
                    <span>$${order.total?.toFixed(2) || '0.00'}</span>
                    <span class="status-badge ${(order.status || 'pending').toLowerCase()}">${order.status || 'Pending'}</span>
                </div>
            </div>
        `).join('');
    }
}

// Render All Orders
function renderAllOrders() {
    const tbody = document.getElementById('allOrdersTable');
    const container = tbody?.parentElement;
    
    // Desktop table
    if (tbody) {
        tbody.innerHTML = allOrders.map(order => `
            <tr>
                <td>${order.orderId}</td>
                <td>${order.customerName || order.customer?.name || 'N/A'}</td>
                <td>${order.items?.length || 0} items</td>
                <td>${new Date(order.createdAt).toLocaleDateString()}</td>
                <td>$${order.total?.toFixed(2) || '0.00'}</td>
                <td>
                    <select onchange="updateOrderStatus('${order._id}', this.value)">
                        <option value="Pending" ${order.status === 'Pending' ? 'selected' : ''}>Pending</option>
                        <option value="Processing" ${order.status === 'Processing' ? 'selected' : ''}>Processing</option>
                        <option value="Shipped" ${order.status === 'Shipped' ? 'selected' : ''}>Shipped</option>
                        <option value="Delivered" ${order.status === 'Delivered' ? 'selected' : ''}>Delivered</option>
                    </select>
                </td>
                <td>
                    <button class="action-btn" onclick="viewOrder('${order._id}')"><i class="fas fa-eye"></i></button>
                    <button class="action-btn delete" onclick="deleteOrder('${order._id}')"><i class="fas fa-trash"></i></button>
                </td>
            </tr>
        `).join('');
    }
    
    // Mobile cards
    if (container) {
        let mobileCards = container.querySelector('.mobile-cards');
        if (!mobileCards) {
            mobileCards = document.createElement('div');
            mobileCards.className = 'mobile-cards';
            container.appendChild(mobileCards);
        }
        
        mobileCards.innerHTML = allOrders.map(order => `
            <div class="order-card-admin">
                <div class="order-card-header">
                    <strong>${order.orderId}</strong>
                    <span class="status-badge ${(order.status || 'pending').toLowerCase()}">${order.status || 'Pending'}</span>
                </div>
                <div class="order-card-info">
                    <p>${order.customerName || order.customer?.name || 'N/A'}</p>
                    <p>${new Date(order.createdAt).toLocaleDateString()} • ${order.items?.length || 0} items</p>
                </div>
                <div class="order-card-total">
                    <span>Total</span>
                    <span>$${order.total?.toFixed(2) || '0.00'}</span>
                </div>
                <div class="order-card-actions">
                    <button class="action-btn" onclick="viewOrder('${order._id}')"><i class="fas fa-eye"></i> View</button>
                    <button class="action-btn" onclick="updateOrderStatusFromCard('${order._id}')"><i class="fas fa-truck"></i> Status</button>
                    <button class="action-btn delete" onclick="deleteOrder('${order._id}')"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `).join('');
    }
}

// Update order status from mobile card
function updateOrderStatusFromCard(orderId) {
    const status = prompt('Enter status (Pending, Processing, Shipped, Delivered):');
    if (status && ['Pending', 'Processing', 'Shipped', 'Delivered'].includes(status)) {
        updateOrderStatus(orderId, status);
    }
}

// Render Products (Desktop Table + Mobile Cards)
function renderProducts() {
    const tbody = document.getElementById('productsTableBody');
    if (!tbody) return;
    
    // Desktop table
    tbody.innerHTML = allProducts.map((p, index) => `
        <tr>
            <td><img src="${p.image}" alt="${p.name}" class="product-thumb" onerror="this.src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNTAiIGhlaWdodD0iNTAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjUwIiBoZWlnaHQ9IjUwIiBmaWxsPSIjZjFmNWY5Ii8+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGRvbWluYW50LWJhc2VsaW5lPSJtaWRkbGUiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZpbGw9IiM5Y2EzYWYiIGZvbnQtZmFtaWx5PSJhcmlhbCIgZm9udC1zaXplPSIxNCI+SW1hZ2U8L3RleHQ+PC9zdmc+'"></td>
            <td>${p.name}</td>
            <td>${p.category}</td>
            <td>${p.tag ? `<span class="tag-badge tag-${p.tag}">${p.tag}</span>` : '-'}</td>
            <td>$${p.price.toFixed(2)}</td>
            <td><span class="stock-badge ${p.stock < 20 ? 'low' : ''}">${p.stock}</span></td>
            <td>
                <button class="action-btn" onclick="editProduct(${index})"><i class="fas fa-edit"></i></button>
                <button class="action-btn delete" onclick="deleteProduct(${index})"><i class="fas fa-trash"></i></button>
            </td>
        </tr>
    `).join('');
}
    
    // Mobile cards
    if (container) {
        let mobileCards = container.querySelector('.mobile-cards');
        if (!mobileCards) {
            mobileCards = document.createElement('div');
            mobileCards.className = 'mobile-cards';
            container.appendChild(mobileCards);
        }
        
        mobileCards.innerHTML = allProducts.map((p, index) => `
            <div class="product-card-admin">
                <img src="${p.image}" alt="${p.name}" onerror="this.src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNzAiIGhlaWdodD0iNzAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjcwIiBoZWlnaHQ9IjcwIiBmaWxsPSIjZjFmNWY5Ii8+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGRvbWluYW50LWJhc2VsaW5lPSJtaWRkbGUiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZpbGw9IiM5Y2EzYWYiIGZvbnQtZmFtaWx5PSJhcmlhbCIgZm9udC1zaXplPSIxNCI+SW1hZ2U8L3RleHQ+PC9zdmc+'">
                <div>
                    <strong>${p.name}</strong>
                    <p>$${p.price.toFixed(2)}</p>
                    <p>${p.tag ? `<span class="tag-badge tag-${p.tag}">${p.tag}</span>` : ''}</p>
                    <span class="stock-badge ${p.stock < 20 ? 'low' : ''}">${p.stock} in stock</span>
                    <div class="action-buttons">
                        <button class="action-btn" data-index="${index}"><i class="fas fa-edit"></i> Edit</button>
                        <button class="action-btn delete" data-index="${index}"><i class="fas fa-trash"></i></button>
                    </div>
                </div>
            </div>
        `).join('');
        
        // Add click handlers for mobile
        mobileCards.querySelectorAll('.action-btn:not(.delete)').forEach(btn => {
            btn.onclick = () => editProduct(parseInt(btn.dataset.index));
        });
        mobileCards.querySelectorAll('.action-btn.delete').forEach(btn => {
            btn.onclick = () => deleteProduct(parseInt(btn.dataset.index));
        });
    }
}

// Show Add Product Form
function showAddProduct() {
    const formHtml = `
        <div class="product-form-modal">
            <h2>Add New Product</h2>
            <form onsubmit="addProduct(event)">
                <input type="text" id="prodName" placeholder="Product Name" required>
                <input type="number" id="prodPrice" placeholder="Price" step="0.01" required>
                <input type="number" id="prodOriginalPrice" placeholder="Original Price (optional)" step="0.01">
                <select id="prodCategory" required>
                    <option value="">Select Category</option>
                    <option value="men">Men</option>
                    <option value="women">Women</option>
                    <option value="kids">Kids</option>
                    <option value="accessories">Accessories</option>
                    <option value="shoes">Shoes</option>
                </select>
                <input type="text" id="prodImage" placeholder="Image URL" required>
                <input type="number" id="prodStock" placeholder="Stock Quantity" required>
                <input type="text" id="prodSizes" placeholder="Sizes (comma separated, e.g., S,M,L,XL)">
                <select id="prodTag">
                    <option value="">No Tag</option>
                    <option value="new">New</option>
                    <option value="sale">Sale</option>
                    <option value="hot">Hot</option>
                </select>
                <textarea id="prodDescription" placeholder="Product Description" rows="3"></textarea>
                <div class="form-buttons">
                    <button type="submit" class="save-btn">Add Product</button>
                    <button type="button" class="cancel-btn" onclick="closeProductForm()">Cancel</button>
                </div>
            </form>
        </div>
    `;
    
    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.innerHTML = `<div class="modal-content">${formHtml}</div>`;
    modal.onclick = (e) => { if (e.target === modal) closeProductForm(); };
    document.body.appendChild(modal);
}

// Close Product Form
function closeProductForm() {
    const modal = document.querySelector('.product-form-modal')?.closest('.modal');
    if (modal) modal.remove();
}

// Add Product
async function addProduct(event) {
    event.preventDefault();
    
    const productData = {
        name: document.getElementById('prodName').value,
        price: parseFloat(document.getElementById('prodPrice').value),
        originalPrice: document.getElementById('prodOriginalPrice').value ? parseFloat(document.getElementById('prodOriginalPrice').value) : null,
        category: document.getElementById('prodCategory').value,
        image: document.getElementById('prodImage').value,
        stock: parseInt(document.getElementById('prodStock').value),
        sizes: document.getElementById('prodSizes').value.split(',').map(s => s.trim()).filter(s => s),
        tag: document.getElementById('prodTag').value,
        description: document.getElementById('prodDescription').value
    };

    try {
        await apiCall('/products', {
            method: 'POST',
            body: JSON.stringify(productData)
        });
        
        closeProductForm();
        await loadProducts();
        await loadStats();
        alert('Product added successfully!');
    } catch (error) {
        alert('Error adding product: ' + error.message);
    }
}

// Edit Product
async function editProduct(index) {
    const product = allProducts[index];
    if (!product) {
        alert('Product not found');
        return;
    }
    
    const productId = product._id;

    const formHtml = `
        <button type="button" class="modal-close" onclick="closeProductForm()" style="position:absolute;top:15px;right:20px;font-size:24px;cursor:pointer;background:none;border:none;">&times;</button>
        <div class="product-form-modal">
            <h2>Edit Product</h2>
            <form onsubmit="updateProduct(event, '${productId}')">
                <input type="text" id="prodName" placeholder="Product Name" value="${product.name}" required>
                <input type="number" id="prodPrice" placeholder="Price" step="0.01" value="${product.price}" required>
                <input type="number" id="prodOriginalPrice" placeholder="Original Price" step="0.01" value="${product.originalPrice || ''}">
                <select id="prodCategory" required>
                    <option value="men" ${product.category === 'men' ? 'selected' : ''}>Men</option>
                    <option value="women" ${product.category === 'women' ? 'selected' : ''}>Women</option>
                    <option value="kids" ${product.category === 'kids' ? 'selected' : ''}>Kids</option>
                    <option value="accessories" ${product.category === 'accessories' ? 'selected' : ''}>Accessories</option>
                    <option value="shoes" ${product.category === 'shoes' ? 'selected' : ''}>Shoes</option>
                </select>
                <input type="text" id="prodImage" placeholder="Image URL" value="${product.image}" required>
                <input type="number" id="prodStock" placeholder="Stock Quantity" value="${product.stock}" required>
                <input type="text" id="prodSizes" placeholder="Sizes" value="${(product.sizes || []).join(', ')}">
                <select id="prodTag">
                    <option value="" ${!product.tag ? 'selected' : ''}>No Tag</option>
                    <option value="new" ${product.tag === 'new' ? 'selected' : ''}>New</option>
                    <option value="sale" ${product.tag === 'sale' ? 'selected' : ''}>Sale</option>
                    <option value="hot" ${product.tag === 'hot' ? 'selected' : ''}>Hot</option>
                </select>
                <textarea id="prodDescription" placeholder="Description" rows="3">${product.description || ''}</textarea>
                <div class="form-buttons">
                    <button type="submit" class="save-btn">Update Product</button>
                    <button type="button" class="cancel-btn" onclick="closeProductForm()">Cancel</button>
                </div>
            </form>
        </div>
    `;
    
    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.id = 'editProductModal';
    modal.innerHTML = `<div class="modal-content admin-modal" style="position:relative;">${formHtml}</div>`;
    modal.onclick = (e) => { if (e.target === modal) closeProductForm(); };
    document.body.appendChild(modal);
}

// Update Product
async function updateProduct(event, productId) {
    event.preventDefault();
    
    const productData = {
        name: document.getElementById('prodName').value,
        price: parseFloat(document.getElementById('prodPrice').value),
        originalPrice: document.getElementById('prodOriginalPrice').value ? parseFloat(document.getElementById('prodOriginalPrice').value) : null,
        category: document.getElementById('prodCategory').value,
        image: document.getElementById('prodImage').value,
        stock: parseInt(document.getElementById('prodStock').value),
        sizes: document.getElementById('prodSizes').value.split(',').map(s => s.trim()).filter(s => s),
        tag: document.getElementById('prodTag').value,
        description: document.getElementById('prodDescription').value
    };

    try {
        await apiCall(`/products/${productId}`, {
            method: 'PUT',
            body: JSON.stringify(productData)
        });
        
        closeProductForm();
        await loadProducts();
        alert('Product updated successfully!');
    } catch (error) {
        alert('Error updating product: ' + error.message);
    }
}

// Delete Product
async function deleteProduct(index) {
    const product = allProducts[index];
    const productId = product._id;
    
    if (!confirm('Are you sure you want to delete this product?')) return;
    
    try {
        await apiCall(`/products/${productId}`, {
            method: 'DELETE'
        });
        
        await loadProducts();
        await loadStats();
        alert('Product deleted successfully!');
    } catch (error) {
        alert('Error deleting product: ' + error.message);
    }
}

// View Order Details
async function viewOrder(orderId) {
    const order = allOrders.find(o => o._id === orderId);
    if (!order) return;

    document.getElementById('orderDetails').innerHTML = `
        <div class="order-detail-header">
            <span>Order #${order.orderId}</span>
            <span class="status-badge ${(order.status || 'pending').toLowerCase()}">${order.status || 'Pending'}</span>
        </div>
        <div class="order-detail-info">
            <p><strong>Date:</strong> ${new Date(order.createdAt).toLocaleString()}</p>
            <p><strong>Customer:</strong> ${order.customerName || order.customer?.name || 'N/A'}</p>
            <p><strong>Email:</strong> ${order.customerEmail || order.customer?.email || 'N/A'}</p>
            <p><strong>Phone:</strong> ${order.shippingAddress?.phone || 'N/A'}</p>
            <p><strong>Address:</strong> ${order.shippingAddress?.address || 'N/A'}, ${order.shippingAddress?.city || ''}</p>
        </div>
        <div class="order-items-list">
            ${(order.items || []).map(item => `
                <div class="order-item-detail">
                    <img src="${item.image}" alt="${item.name}" onerror="this.src='https://via.placeholder.com/50'">
                    <div>
                        <h4>${item.name}</h4>
                        <p>Qty: ${item.quantity} × $${item.price}</p>
                        ${item.size ? `<p>Size: ${item.size}</p>` : ''}
                    </div>
                    <span>$${((item.quantity || 1) * (item.price || 0)).toFixed(2)}</span>
                </div>
            `).join('')}
        </div>
        <div class="order-total-detail">
            <div><span>Subtotal:</span><span>$${order.subtotal?.toFixed(2) || '0.00'}</span></div>
            <div><span>Tax:</span><span>$${order.tax?.toFixed(2) || '0.00'}</span></div>
            <div><span>Shipping:</span><span>$${order.shipping?.toFixed(2) || '0.00'}</span></div>
            <div class="total"><span>Total:</span><span>$${order.total?.toFixed(2) || '0.00'}</span></div>
        </div>
    `;
    document.getElementById('orderModal').style.display = 'flex';
}

// Update Order Status
async function updateOrderStatus(orderId, status) {
    console.log('Updating order:', orderId, 'to status:', status);
    console.log('Using API URL:', API_URL);
    console.log('Auth Token:', authToken ? 'Present' : 'Missing');
    
    if (!orderId || orderId === 'undefined' || orderId === 'null') {
        alert('Error: Order ID is missing. Please refresh the page and try again.');
        return;
    }
    
    if (!authToken) {
        alert('Error: Admin not logged in. Please refresh the page.');
        return;
    }
    
    try {
        // Direct fetch call to see full response
        const response = await fetch(`${API_URL}/orders/${orderId}/status?t=${Date.now()}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ status })
        });
        
        console.log('Response status:', response.status);
        const text = await response.text();
        console.log('Response text:', text.substring(0, 500));
        
        if (!response.ok) {
            if (text.includes('<!DOCTYPE') || text.includes('<html')) {
                throw new Error('API returned error page. Backend may not be updated or URL is wrong.');
            }
            const data = JSON.parse(text);
            throw new Error(data.message || 'Request failed');
        }
        
        const result = JSON.parse(text);
        console.log('Update result:', result);
        await loadOrders();
        alert('Order status updated to ' + status + '!');
    } catch (error) {
        console.error('Error updating order:', error);
        alert('Error: ' + error.message + '\n\nAPI: ' + API_URL + '\n\nToken: ' + (authToken ? 'OK' : 'Missing'));
    }
}

// Close Order Modal
function closeOrderModal() {
    document.getElementById('orderModal').style.display = 'none';
}

// Delete Order
async function deleteOrder(orderId) {
    if (!confirm('Are you sure you want to delete this order?')) return;
    
    try {
        await apiCall(`/orders/${orderId}`, {
            method: 'DELETE'
        });
        
        await loadOrders();
        await loadStats();
        alert('Order deleted successfully!');
    } catch (error) {
        alert('Error deleting order: ' + error.message);
    }
}

// Logout
function logoutAdmin() {
    localStorage.removeItem('velvoraAdminToken');
    localStorage.removeItem('velvoraAdminUser');
    window.location.href = 'login.html';
}

function resetDemoData() {
    if (confirm('Reset all demo data to defaults? This will clear all your product changes.')) {
        localStorage.removeItem('velvoraProducts');
        allProducts = getStoredProducts();
        renderProducts();
        document.getElementById('totalProducts').textContent = allProducts.length;
        alert('Demo data has been reset!');
    }
}

// Navigation
function showAdminSection(section) {
    document.querySelectorAll('.admin-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.admin-menu li').forEach(l => l.classList.remove('active'));
    
    document.getElementById(section).classList.add('active');
    event.target.closest('li')?.classList.add('active');
    
    const titles = { dashboard: 'Dashboard', orders: 'Orders', products: 'Products', customers: 'Customers', analytics: 'Analytics' };
    document.getElementById('pageTitle').textContent = titles[section];
    
    // Load customers when clicking customers tab
    if (section === 'customers') {
        loadCustomers();
    }
    
    // Close sidebar on mobile
    if (window.innerWidth <= 768) {
        document.querySelector('.admin-sidebar').classList.remove('active');
    }
    
    // Update mobile nav active state
    updateMobileNavState(section);
}

// Mobile Nav Click Handler
function showMobileNav(section, event) {
    document.querySelectorAll('.admin-section').forEach(s => s.classList.remove('active'));
    document.getElementById(section).classList.add('active');
    
    const titles = { dashboard: 'Dashboard', orders: 'Orders', products: 'Products', customers: 'Customers', analytics: 'Analytics' };
    document.getElementById('pageTitle').textContent = titles[section];
    
    // Update mobile nav active state
    updateMobileNavState(section);
}

function updateMobileNavState(section) {
    document.querySelectorAll('.mobile-nav button').forEach(btn => btn.classList.remove('active'));
    const navButtons = {
        'dashboard': 0,
        'products': 1,
        'orders': 2,
        'analytics': 3
    };
    if (navButtons[section] !== undefined) {
        document.querySelectorAll('.mobile-nav button')[navButtons[section]]?.classList.add('active');
    }
}

// Toggle Sidebar
function toggleSidebar() {
    document.querySelector('.admin-sidebar').classList.toggle('active');
}

// Initialize on load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAdmin);
} else {
    initAdmin();
}

// Set initial mobile nav state
document.addEventListener('DOMContentLoaded', () => {
    updateMobileNavState('dashboard');
    initImageUpload();
    initCharts();
});

// Image Upload with Cropper
function initImageUpload() {
    const dropArea = document.getElementById('dropArea');
    const imageInput = document.getElementById('imageInput');
    const cropperContainer = document.getElementById('cropperContainer');
    const cropperImage = document.getElementById('cropperImage');
    const cropBtn = document.getElementById('cropBtn');
    
    if (!dropArea || !imageInput) return;
    
    dropArea.addEventListener('click', () => imageInput.click());
    
    dropArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropArea.classList.add('dragover');
    });
    
    dropArea.addEventListener('dragleave', () => {
        dropArea.classList.remove('dragover');
    });
    
    dropArea.addEventListener('drop', (e) => {
        e.preventDefault();
        dropArea.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length) handleImageSelect(files[0]);
    });
    
    imageInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleImageSelect(e.target.files[0]);
    });
    
    function handleImageSelect(file) {
        if (!file.type.startsWith('image/')) {
            alert('Please select an image file');
            return;
        }
        
        const reader = new FileReader();
        reader.onload = (e) => {
            cropperImage.src = e.target.result;
            cropperContainer.style.display = 'block';
            cropBtn.style.display = 'inline-flex';
            dropArea.style.display = 'none';
            
            if (cropper) cropper.destroy();
            
            cropper = new Cropper(cropperImage, {
                aspectRatio: 1,
                viewMode: 1,
                background: false,
                autoCropArea: 1
            });
        };
        reader.readAsDataURL(file);
    }
}

function cropImage() {
    if (!cropper) return;
    
    const canvas = cropper.getCroppedCanvas({
        width: 800,
        height: 800,
        imageSmoothingEnabled: true,
        imageSmoothingQuality: 'high'
    });
    
    const croppedImage = canvas.toDataURL('image/jpeg', 0.9);
    
    // Set the cropped image to the input field
    const imageInput = document.getElementById('prodImage');
    if (imageInput) {
        imageInput.value = croppedImage;
    }
    
    closeImageModal();
}

function openImageUpload(callback) {
    currentImageCallback = callback;
    document.getElementById('imageUploadModal').classList.add('active');
}

function closeImageModal() {
    const modal = document.getElementById('imageUploadModal');
    modal.classList.remove('active');
    
    const dropArea = document.getElementById('dropArea');
    const cropperContainer = document.getElementById('cropperContainer');
    const cropBtn = document.getElementById('cropBtn');
    const imageInput = document.getElementById('imageInput');
    
    if (dropArea) dropArea.style.display = 'block';
    if (cropperContainer) cropperContainer.style.display = 'none';
    if (cropBtn) cropBtn.style.display = 'none';
    if (imageInput) imageInput.value = '';
    
    if (cropper) {
        cropper.destroy();
        cropper = null;
    }
}

// Initialize Charts
let revenueChart = null;
let ordersChart = null;

function initCharts() {
    // Destroy existing charts first
    const revenueCtx = document.getElementById('revenueChart');
    const ordersCtx = document.getElementById('ordersStatusChart');
    
    if (revenueCtx) {
        if (revenueChart) {
            revenueChart.destroy();
        }
        revenueChart = null;
    }
    if (ordersCtx) {
        if (ordersChart) {
            ordersChart.destroy();
        }
        ordersChart = null;
    }
    
    // Revenue Chart
    if (revenueCtx) {
        revenueChart = new Chart(revenueCtx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'Revenue',
                    data: [5000, 8000, 12000, 9000, 15000, 20000],
                    borderColor: '#c8a96a',
                    backgroundColor: 'rgba(200, 169, 106, 0.1)',
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2,
                    pointBackgroundColor: '#c8a96a',
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(0,0,0,0.05)' }
                    },
                    x: {
                        grid: { display: false }
                    }
                }
            }
        });
    }
    
    // Orders Status Chart
    const ordersCtx = document.getElementById('ordersStatusChart');
    if (ordersCtx) {
        const statusCounts = {
            Pending: allOrders.filter(o => o.status === 'Pending').length,
            Processing: allOrders.filter(o => o.status === 'Processing').length,
            Shipped: allOrders.filter(o => o.status === 'Shipped').length,
            Delivered: allOrders.filter(o => o.status === 'Delivered').length
        };
        
        new Chart(ordersCtx, {
            type: 'doughnut',
            data: {
                labels: ['Pending', 'Processing', 'Shipped', 'Delivered'],
                datasets: [{
                    data: [statusCounts.Pending || 1, statusCounts.Processing || 0, statusCounts.Shipped || 0, statusCounts.Delivered || 0],
                    backgroundColor: ['#ffc107', '#0d6efd', '#6f42c1', '#198754'],
                    borderWidth: 0,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 15, usePointStyle: true }
                    }
                },
                cutout: '65%'
            }
        });
    }
    
    // Top Products
    renderTopProducts();
}

function renderTopProducts() {
    const container = document.getElementById('topProductsList');
    if (!container) return;
    
    if (allProducts.length === 0) {
        container.innerHTML = '<p class="no-data">No products yet</p>';
        return;
    }
    
    const topProducts = allProducts.slice(0, 5).map((p, index) => `
        <div class="top-product-item">
            <span class="rank">${index + 1}</span>
            <img src="${p.image}" alt="${p.name}" onerror="this.src='https://via.placeholder.com/40'">
            <div class="top-product-info">
                <strong>${p.name}</strong>
                <span>${p.stock} in stock</span>
            </div>
            <span class="price">$${p.price.toFixed(2)}</span>
        </div>
    `).join('');
    
    container.innerHTML = topProducts;
}

// Animate Stats Counter
function animateValue(elementId, start, end, duration = 1000) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            current = end;
            clearInterval(timer);
        }
        if (elementId.includes('Revenue')) {
            element.textContent = '$' + Math.floor(current).toLocaleString();
        } else {
            element.textContent = '$' + current.toFixed(2);
        }
    }, 16);
}
