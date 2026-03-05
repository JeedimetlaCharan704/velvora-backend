const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/api/health', (req, res) => {
  const mongoState = mongoose.connection.readyState;
  const mongoStates = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  res.json({ 
    status: 'ok', 
    message: 'Velvora API running',
    mongoDB: mongoStates[mongoState],
    mongoUriSet: !!process.env.MONGODB_URI,
    mongoUri: process.env.MONGODB_URI ? process.env.MONGODB_URI.replace(/\/\/.*:.*@/, '//***:***@') : null
  });
});

app.get('/api/test-mongo', async (req, res) => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
    res.json({ status: 'connected', message: 'MongoDB working!' });
  } catch (err) {
    res.json({ status: 'error', message: err.message });
  }
});

const JWT_SECRET = 'velvora_admin_secret_key_2024';

console.log('Connecting to MongoDB...');
console.log('MongoDB URI set:', !!process.env.MONGODB_URI);

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/velvora', {
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB Error:', err.message));

const productSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  originalPrice: Number,
  category: String,
  image: String,
  stock: Number,
  sizes: [String],
  colors: [String],
  tag: String,
  rating: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
  orderId: String,
  customer: {
    name: String,
    email: String,
    phone: String,
    address: String
  },
  items: [{
    name: String,
    price: Number,
    quantity: Number,
    size: String,
    color: String,
    image: String
  }],
  total: Number,
  status: { type: String, default: 'Processing' },
  paymentMethod: String,
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  phone: String,
  address: String,
  role: { type: String, default: 'user' },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const adminAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email, role: 'admin' });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }
  
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }
  
  const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role = 'user' } = req.body;
  
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashedPassword, role });
  await user.save();
  
  const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/auth/user/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }
  
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }
  
  const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user._id, name: user.name, email: user.email, phone: user.phone, address: user.address, role: user.role } });
});

app.get('/api/products', async (req, res) => {
  const products = await Product.find().sort({ createdAt: -1 });
  res.json(products);
});

app.get('/api/products/admin/all', adminAuth, async (req, res) => {
  const products = await Product.find().sort({ createdAt: -1 });
  res.json(products);
});

app.get('/api/products/:id', async (req, res) => {
  const product = await Product.findById(req.params.id);
  res.json(product);
});

app.post('/api/products', adminAuth, async (req, res) => {
  const product = new Product(req.body);
  await product.save();
  res.json(product);
});

app.put('/api/products/:id', adminAuth, async (req, res) => {
  const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(product);
});

app.delete('/api/products/:id', adminAuth, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: 'Product deleted' });
});

app.get('/api/orders', adminAuth, async (req, res) => {
  const orders = await Order.find().sort({ createdAt: -1 });
  res.json({ orders, total: orders.length });
});

app.get('/api/orders/:id', adminAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

app.post('/api/orders', async (req, res) => {
  const order = new Order(req.body);
  await order.save();
  res.json(order);
});

app.put('/api/orders/:id', adminAuth, async (req, res) => {
  const order = await Order.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(order);
});

app.get('/api/orders/stats/summary', adminAuth, async (req, res) => {
  const orders = await Order.find();
  const totalOrders = orders.length;
  const totalRevenue = orders.reduce((sum, o) => sum + (o.total || 0), 0);
  res.json({ totalOrders, totalRevenue });
});

app.get('/api/users', adminAuth, async (req, res) => {
  const users = await User.find({ role: 'user' }).sort({ createdAt: -1 });
  res.json(users);
});

app.get('/api/products/category/:category', async (req, res) => {
  const products = await Product.find({ category: req.params.category });
  res.json(products);
});

const seedProducts = [
  { name: "Silk Evening Gown", price: 299.99, originalPrice: 399.99, image: "https://images.unsplash.com/photo-1595777457583-95e059d581b8?w=600&h=600&fit=crop&q=80", category: "women", tag: "new", rating: 5, sizes: ["S", "M", "L", "XL"], stock: 20 },
  { name: "Premium Leather Jacket", price: 449.99, originalPrice: 549.99, image: "https://images.unsplash.com/photo-1551028719-00167b16eac5?w=600&h=600&fit=crop&q=80", category: "men", tag: "new", rating: 5, sizes: ["S", "M", "L", "XL", "XXL"], stock: 15 },
  { name: "Designer Sunglasses", price: 189.99, originalPrice: 249.99, image: "https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=600&h=600&fit=crop&q=80", category: "accessories", tag: "sale", rating: 4, sizes: [], stock: 50 },
  { name: "Cashmere Sweater", price: 199.99, originalPrice: 279.99, image: "https://images.unsplash.com/photo-1576566588028-4147f3842f27?w=600&h=600&fit=crop&q=80", category: "women", tag: "sale", rating: 5, sizes: ["S", "M", "L", "XL"], stock: 30 },
  { name: "Classic Denim Jeans", price: 89.99, originalPrice: 129.99, image: "https://images.unsplash.com/photo-1542272604-787c3835535d?w=600&h=600&fit=crop&q=80", category: "men", tag: "new", rating: 4, sizes: ["28", "30", "32", "34", "36"], stock: 45 },
  { name: "Floral Summer Dress", price: 79.99, originalPrice: 99.99, image: "https://images.unsplash.com/photo-1572804013309-59a88b7e92f1?w=600&h=600&fit=crop&q=80", category: "women", tag: "sale", rating: 4, sizes: ["S", "M", "L", "XL"], stock: 35 },
  { name: "Leather Belt", price: 49.99, originalPrice: 69.99, image: "https://images.unsplash.com/photo-1624222247344-550fb60583dc?w=600&h=600&fit=crop&q=80", category: "accessories", tag: "sale", rating: 4, sizes: [], stock: 60 },
  { name: "Kids Party Wear", price: 59.99, originalPrice: 79.99, image: "https://images.unsplash.com/photo-1519235106638-35e35556b40d?w=600&h=600&fit=crop&q=80", category: "kids", tag: "new", rating: 5, sizes: ["S", "M", "L", "XL"], stock: 25 },
  { name: "Wool Blazer", price: 349.99, originalPrice: 449.99, image: "https://images.unsplash.com/photo-1507679799987-c73779587ccf?w=600&h=600&fit=crop&q=80", category: "men", tag: "new", rating: 5, sizes: ["S", "M", "L", "XL", "XXL"], stock: 18 },
  { name: "Pearl Earrings", price: 89.99, originalPrice: 119.99, image: "https://images.unsplash.com/photo-1535632066927-ab7c9ab60908?w=600&h=600&fit=crop&q=80", category: "accessories", tag: "new", rating: 4, sizes: [], stock: 40 }
];

app.post('/api/seed', async (req, res) => {
  try {
    await Product.deleteMany({});
    await Product.insertMany(seedProducts);
    res.json({ message: 'Products seeded successfully', count: seedProducts.length });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/seed', async (req, res) => {
  try {
    await Product.deleteMany({});
    await Product.insertMany(seedProducts);
    res.json({ message: 'Products seeded successfully', count: seedProducts.length });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
