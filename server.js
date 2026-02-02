const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
const http = require('http');
const socketIo = require('socket.io');

// Load environment variables
dotenv.config();

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const postRoutes = require('./routes/posts');
const friendRoutes = require('./routes/friends');
const chatRoutes = require('./routes/chats');
const storyRoutes = require('./routes/stories');
const notificationRoutes = require('./routes/notifications');
const marketplaceRoutes = require('./routes/marketplace');
const groupRoutes = require('./routes/groups');

// Import middleware
const { errorHandler } = require('./middleware/errorMiddleware');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    credentials: true
  }
});

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Body parser
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static files
app.use('/uploads', express.static('public/uploads'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/posts', postRoutes);
app.use('/api/friends', friendRoutes);
app.use('/api/chats', chatRoutes);
app.use('/api/stories', storyRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/marketplace', marketplaceRoutes);
app.use('/api/groups', groupRoutes);

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Error handler
app.use(errorHandler);

// WebSocket connection
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  // Join user's room
  socket.on('join-user', (userId) => {
    socket.join(`user-${userId}`);
    console.log(`User ${userId} joined room`);
  });
  
  // Handle messaging
  socket.on('send-message', async (data) => {
    const { receiverId, message, senderId } = data;
    
    // Save message to database (implementation in chatController)
    // Broadcast to receiver
    socket.to(`user-${receiverId}`).emit('receive-message', {
      senderId,
      message,
      timestamp: new Date()
    });
  });
  
  // Handle typing indicator
  socket.on('typing', (data) => {
    socket.to(`user-${data.receiverId}`).emit('user-typing', {
      senderId: data.senderId,
      isTyping: data.isTyping
    });
  });
  
  // Handle online status
  socket.on('user-online', (userId) => {
    socket.broadcast.emit('friend-online', userId);
  });
  
  // Handle disconnect
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/friendsconnect', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
