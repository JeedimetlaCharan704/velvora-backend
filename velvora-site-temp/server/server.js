require('dotenv').config();
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
  orderId: { type: String, unique: true },
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
  subtotal: Number,
  tax: Number,
  shipping: Number,
  total: Number,
  status: { type: String, default: 'Pending' },
  paymentMethod: String,
  shippingAddress: {
    address: String,
    city: String,
    postalCode: String,
    country: String,
    phone: String
  },
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
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ message: 'Product not found' });
  
  Object.assign(product, req.body);
  await product.save();
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
  const orderId = 'ORD-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
  const order = new Order({ ...req.body, orderId });
  await order.save();
  res.json(order);
});

app.put('/api/orders/:id/status', adminAuth, async (req, res) => {
  try {
    const order = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json(order);
  } catch (err) {
    res.status(400).json({ message: 'Invalid order ID format' });
  }
});

app.delete('/api/orders/:id', adminAuth, async (req, res) => {
  await Order.findByIdAndDelete(req.params.id);
  res.json({ message: 'Order deleted' });
});

app.get('/api/users/orders', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const orders = await Order.find({ 'customer.email': decoded.email }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
