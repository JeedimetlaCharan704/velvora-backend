// API Configuration
const API_URL = localStorage.getItem('apiUrl') || 'http://localhost:5000/api';
let authToken = localStorage.getItem('velvoraAdminToken');
let allProducts = [];
let allOrders = [];

// Helper function for API calls
async function apiCall(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...(authToken && { Authorization: `Bearer ${authToken}` }),
        ...options.headers
    };

    const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        headers
    });

    if (response.status === 401) {
        logoutAdmin();
        throw new Error('Session expired');
    }

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.message || 'Something went wrong');
    }
    return data;
}

// Load Products
async function loadProducts() {
    try {
        const data = await apiCall('/products/admin/all');
        allProducts = data;
        renderProducts();
        document.getElementById('totalProducts').textContent = data.length;
    } catch (error) {
        console.error('Error loading products:', error);
    }
}

// Load Orders
async function loadOrders() {
    try {
        const data = await apiCall('/orders');
        allOrders = data.orders || data;
        renderOrders();
        
        if (data.total !== undefined) {
            document.getElementById('totalOrders').textContent = data.total;
        }
        
        const totalRevenue = allOrders.reduce((sum, o) => sum + (o.total || 0), 0);
        document.getElementById('totalRevenue').textContent = '$' + totalRevenue.toFixed(2);
    } catch (error) {
        console.error('Error loading orders:', error);
    }
}

// Load Stats
async function loadStats() {
    try {
        const stats = await apiCall('/orders/stats/summary');
        
        if (document.getElementById('totalOrders')) {
            document.getElementById('totalOrders').textContent = stats.totalOrders || 0;
        }
        if (document.getElementById('totalRevenue')) {
            document.getElementById('totalRevenue').textContent = '$' + (stats.totalRevenue || 0).toFixed(2);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Render Products
function renderProducts() {
    const tbody = document.getElementById('productsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = allProducts.map(p => `
        <tr>
            <td><img src="${p.image || 'https://via.placeholder.com/50'}" alt="${p.name}" style="width:50px;height:50px;object-fit:cover;border-radius:5px;"></td>
            <td>${p.name}</td>
            <td>$${p.price?.toFixed(2) || '0.00'}</td>
            <td>${p.stock || 0}</td>
        </tr>
    `).join('');
}

// Render Orders
function renderOrders() {
    const tbody = document.getElementById('allOrdersTable');
    const recentTbody = document.getElementById('recentOrdersTable');
    
    if (tbody) {
        tbody.innerHTML = allOrders.map(order => `
            <tr>
                <td>${order.orderId || 'N/A'}</td>
                <td>${order.customerName || 'N/A'}</td>
                <td>$${order.total?.toFixed(2) || '0.00'}</td>
                <td>${order.status || 'Pending'}</td>
            </tr>
        `).join('');
    }
    
    if (recentTbody) {
        recentTbody.innerHTML = allOrders.slice(0, 5).map(order => `
            <tr>
                <td>${order.orderId || 'N/A'}</td>
                <td>${order.customerName || 'N/A'}</td>
                <td>$${order.total?.toFixed(2) || '0.00'}</td>
                <td>${order.status || 'Pending'}</td>
            </tr>
        `).join('');
    }
}

// Save Product
async function saveProduct() {
    const productData = {
        name: document.getElementById('prodName').value,
        price: document.getElementById('prodPrice').value,
        category: document.getElementById('prodCategory').value,
        image: document.getElementById('prodImage').value || 'https://via.placeholder.com/300',
        stock: document.getElementById('prodStock').value,
        tag: 'new',
        sizes: []
    };

    try {
        await apiCall('/products', {
            method: 'POST',
            body: JSON.stringify(productData)
        });
        
        document.getElementById('productModal').style.display = 'none';
        await loadProducts();
        alert('Product added!');
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Logout
function logoutAdmin() {
    localStorage.removeItem('velvoraAdminToken');
    localStorage.removeItem('velvoraAdminUser');
    location.reload();
}
