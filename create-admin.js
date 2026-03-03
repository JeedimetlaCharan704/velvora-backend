const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/velvora');

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

async function createAdmin() {
  const hashedPassword = await bcrypt.hash('admin123', 10);
  const admin = new User({
    name: 'Admin',
    email: 'admin@velvora.com',
    password: hashedPassword,
    role: 'admin'
  });
  await admin.save();
  console.log('Admin created: admin@velvora.com / admin123');
  process.exit();
}

createAdmin();
