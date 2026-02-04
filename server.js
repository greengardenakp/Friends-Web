require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const http = require('http');
const socketIo = require('socket.io');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        credentials: true
    }
});

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true
}));
app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000 // Increased for development
});
app.use('/api/', limiter);

// Database connection pool with your credentials
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'system',
    password: process.env.DB_PASSWORD || '783145',
    database: process.env.DB_NAME || 'friendsconnect',
    waitForConnections: true,
    connectionLimit: 20, // Increased connection limit
    queueLimit: 0,
    connectTimeout: 10000, // 10 seconds
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.getConnection()
    .then(connection => {
        console.log('✅ Database connected successfully');
        connection.release();
    })
    .catch(err => {
        console.error('❌ Database connection failed:', err.message);
        console.log('Trying to create database...');
        createDatabase();
    });

async function createDatabase() {
    try {
        const tempPool = mysql.createPool({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD
        });
        
        await tempPool.execute(`CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME}`);
        console.log(`✅ Database ${process.env.DB_NAME} created or already exists`);
        await tempPool.end();
    } catch (err) {
        console.error('❌ Failed to create database:', err.message);
    }
}

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = `uploads/${file.fieldname}s`;
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = {
            'profile': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
            'cover': ['image/jpeg', 'image/png', 'image/webp'],
            'post': ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/quicktime'],
            'message': ['image/jpeg', 'image/png', 'image/gif', 'audio/mpeg', 'video/mp4', 'application/pdf'],
            'group': ['image/jpeg', 'image/png', 'image/webp'],
            'story': ['image/jpeg', 'image/png', 'image/gif', 'video/mp4']
        };
        
        const fieldname = file.fieldname.split('_')[0];
        if (allowedTypes[fieldname] && allowedTypes[fieldname].includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error(`Invalid file type for ${fieldname}. Allowed: ${allowedTypes[fieldname]?.join(', ')}`));
        }
    }
});

// Email transporter configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Verify email configuration
transporter.verify(function(error, success) {
    if (error) {
        console.log('❌ Email configuration error:', error);
    } else {
        console.log('✅ Email server is ready to send messages');
    }
});

// Utility functions
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
const generateToken = () => crypto.randomBytes(32).toString('hex');
const isImage = (mimetype) => mimetype.startsWith('image/');
const isVideo = (mimetype) => mimetype.startsWith('video/');
const isAudio = (mimetype) => mimetype.startsWith('audio/');

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'friendsconnect-secret-key-2024';

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: 'Access token required',
            code: 'TOKEN_REQUIRED'
        });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await pool.execute(
            'SELECT id, username, email, full_name, profile_pic, is_verified, is_online, account_status FROM users WHERE id = ?',
            [decoded.userId]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        const user = users[0];
        
        if (user.account_status !== 'active') {
            return res.status(403).json({ 
                success: false, 
                error: 'Account is suspended or banned',
                code: 'ACCOUNT_SUSPENDED'
            });
        }
        
        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                error: 'Token expired',
                code: 'TOKEN_EXPIRED'
            });
        }
        return res.status(403).json({ 
            success: false, 
            error: 'Invalid token',
            code: 'INVALID_TOKEN'
        });
    }
};

// Socket.IO connection handling
const onlineUsers = new Map();

io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);
    
    socket.on('authenticate', async (token) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const [users] = await pool.execute(
                'SELECT id, username FROM users WHERE id = ? AND account_status = "active"',
                [decoded.userId]
            );
            
            if (users.length > 0) {
                const user = users[0];
                socket.userId = user.id;
                socket.username = user.username;
                onlineUsers.set(user.id, socket.id);
                
                // Update online status
                await pool.execute(
                    'UPDATE users SET is_online = TRUE, last_seen = NOW() WHERE id = ?',
                    [user.id]
                );
                
                // Notify friends about online status
                const [friends] = await pool.execute(
                    `SELECT user1_id, user2_id FROM friendships 
                     WHERE user1_id = ? OR user2_id = ?`,
                    [user.id, user.id]
                );
                
                friends.forEach(friend => {
                    const friendId = friend.user1_id === user.id ? friend.user2_id : friend.user1_id;
                    const friendSocketId = onlineUsers.get(friendId);
                    if (friendSocketId) {
                        io.to(friendSocketId).emit('user_online', { 
                            userId: user.id,
                            username: user.username
                        });
                    }
                });
                
                console.log(`✅ User ${user.username} (${user.id}) authenticated on socket ${socket.id}`);
            }
        } catch (error) {
            console.error('Socket authentication error:', error.message);
        }
    });
    
    socket.on('join_conversation', (conversationId) => {
        socket.join(`conversation_${conversationId}`);
        console.log(`User ${socket.userId} joined conversation ${conversationId}`);
    });
    
    socket.on('leave_conversation', (conversationId) => {
        socket.leave(`conversation_${conversationId}`);
        console.log(`User ${socket.userId} left conversation ${conversationId}`);
    });
    
    socket.on('typing', async ({ conversationId, isTyping }) => {
        if (socket.userId) {
            try {
                await pool.execute(
                    'INSERT INTO typing_indicators (conversation_id, user_id, is_typing) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE is_typing = ?, updated_at = NOW()',
                    [conversationId, socket.userId, isTyping, isTyping]
                );
                
                socket.to(`conversation_${conversationId}`).emit('user_typing', {
                    userId: socket.userId,
                    username: socket.username,
                    conversationId,
                    isTyping
                });
            } catch (error) {
                console.error('Typing indicator error:', error);
            }
        }
    });
    
    socket.on('message_read', async ({ messageId, conversationId }) => {
        if (socket.userId) {
            try {
                await pool.execute(
                    'INSERT INTO message_reads (message_id, user_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE read_at = NOW()',
                    [messageId, socket.userId]
                );
                
                // Mark all previous messages as read
                await pool.execute(
                    `UPDATE messages m
                     LEFT JOIN message_reads mr ON m.id = mr.message_id AND mr.user_id = ?
                     SET m.is_read = TRUE
                     WHERE m.conversation_id = ? AND m.sender_id != ? AND mr.id IS NULL AND m.id <= ?`,
                    [socket.userId, conversationId, socket.userId, messageId]
                );
                
                socket.to(`conversation_${conversationId}`).emit('messages_read', {
                    userId: socket.userId,
                    conversationId,
                    messageId
                });
            } catch (error) {
                console.error('Message read error:', error);
            }
        }
    });
    
    socket.on('disconnect', async () => {
        if (socket.userId) {
            onlineUsers.delete(socket.userId);
            
            try {
                await pool.execute(
                    'UPDATE users SET is_online = FALSE, last_seen = NOW() WHERE id = ?',
                    [socket.userId]
                );
                
                // Notify friends about offline status
                const [friends] = await pool.execute(
                    `SELECT user1_id, user2_id FROM friendships 
                     WHERE user1_id = ? OR user2_id = ?`,
                    [socket.userId, socket.userId]
                );
                
                friends.forEach(friend => {
                    const friendId = friend.user1_id === socket.userId ? friend.user2_id : friend.user1_id;
                    const friendSocketId = onlineUsers.get(friendId);
                    if (friendSocketId) {
                        io.to(friendSocketId).emit('user_offline', { 
                            userId: socket.userId 
                        });
                    }
                });
                
                console.log(`User ${socket.userId} disconnected`);
            } catch (error) {
                console.error('Disconnect error:', error);
            }
        }
    });
});

// API Routes

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        await pool.execute('SELECT 1');
        res.json({ 
            success: true, 
            message: 'Server is running', 
            database: 'Connected',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            error: 'Database connection failed',
            message: error.message 
        });
    }
});

// 1. AUTHENTICATION ROUTES
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, full_name, birthdate } = req.body;
        
        // Validation
        if (!username || !email || !password || !full_name) {
            return res.status(400).json({ 
                success: false, 
                error: 'All fields are required',
                code: 'MISSING_FIELDS'
            });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ 
                success: false, 
                error: 'Password must be at least 6 characters',
                code: 'PASSWORD_TOO_SHORT'
            });
        }
        
        // Check if user exists
        const [existing] = await pool.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [email, username]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'User already exists',
                code: 'USER_EXISTS'
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const [result] = await pool.execute(
            `INSERT INTO users (username, email, password_hash, full_name, birthdate) 
             VALUES (?, ?, ?, ?, ?)`,
            [username, email, hashedPassword, full_name, birthdate || null]
        );
        
        const userId = result.insertId;
        
        // Generate verification OTP
        const otp = generateOTP();
        await pool.execute(
            'INSERT INTO email_verifications (user_id, email, otp_code, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
            [userId, email, otp]
        );
        
        // Send verification email
        try {
            await transporter.sendMail({
                from: `"FriendsConnect" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: 'Verify Your FriendsConnect Account',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #6366f1;">Welcome to FriendsConnect!</h2>
                        <p>Hello ${full_name},</p>
                        <p>Thank you for registering. Your verification code is:</p>
                        <div style="background: #f3f4f6; padding: 20px; text-align: center; font-size: 32px; letter-spacing: 5px; margin: 20px 0; border-radius: 8px;">
                            <strong>${otp}</strong>
                        </div>
                        <p>This code will expire in 10 minutes.</p>
                        <p>If you didn't create this account, you can safely ignore this email.</p>
                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                        <p style="color: #6b7280; font-size: 12px;">This is an automated message, please do not reply.</p>
                    </div>
                `
            });
        } catch (emailError) {
            console.error('Email sending failed:', emailError);
            // Continue even if email fails
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: userId },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        // Get user data
        const [users] = await pool.execute(
            'SELECT id, username, email, full_name, profile_pic, is_verified, is_online FROM users WHERE id = ?',
            [userId]
        );
        
        res.status(201).json({
            success: true,
            message: 'Registration successful. Please verify your email.',
            token,
            user: users[0],
            requiresVerification: true
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Registration failed',
            code: 'REGISTRATION_FAILED',
            message: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, device_info, ip_address } = req.body;
        
        // Validation
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and password are required',
                code: 'MISSING_CREDENTIALS'
            });
        }
        
        // Find user
        const [users] = await pool.execute(
            'SELECT id, password_hash, is_verified, account_status FROM users WHERE email = ?',
            [email]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid email or password',
                code: 'INVALID_CREDENTIALS'
            });
        }
        
        const user = users[0];
        
        // Check account status
        if (user.account_status !== 'active') {
            return res.status(403).json({ 
                success: false, 
                error: 'Account is suspended or banned',
                code: 'ACCOUNT_SUSPENDED'
            });
        }
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid email or password',
                code: 'INVALID_CREDENTIALS'
            });
        }
        
        // Check if email is verified
        if (!user.is_verified) {
            return res.status(403).json({ 
                success: false, 
                error: 'Please verify your email first',
                code: 'EMAIL_NOT_VERIFIED',
                requiresVerification: true
            });
        }
        
        // Create session
        const sessionToken = generateToken();
        await pool.execute(
            'INSERT INTO sessions (user_id, session_token, device_info, ip_address, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))',
            [user.id, sessionToken, device_info || 'Unknown', ip_address || 'Unknown']
        );
        
        // Log login
        await pool.execute(
            'INSERT INTO login_history (user_id, ip_address, user_agent, device_type, location) VALUES (?, ?, ?, ?, ?)',
            [user.id, ip_address || 'Unknown', req.headers['user-agent'] || 'Unknown', 'web', 'Unknown']
        );
        
        // Update online status
        await pool.execute(
            'UPDATE users SET is_online = TRUE, last_seen = NOW() WHERE id = ?',
            [user.id]
        );
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, sessionToken },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        // Get user data
        const [userData] = await pool.execute(
            'SELECT id, username, email, full_name, profile_pic, is_verified, is_online, theme_preference FROM users WHERE id = ?',
            [user.id]
        );
        
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: userData[0],
            sessionToken
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Login failed',
            code: 'LOGIN_FAILED'
        });
    }
});

app.post('/api/auth/verify-email', async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        if (!email || !otp) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and OTP are required',
                code: 'MISSING_DATA'
            });
        }
        
        const [verifications] = await pool.execute(
            'SELECT * FROM email_verifications WHERE email = ? AND otp_code = ? AND is_used = FALSE AND expires_at > NOW()',
            [email, otp]
        );
        
        if (verifications.length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid or expired OTP',
                code: 'INVALID_OTP'
            });
        }
        
        const verification = verifications[0];
        
        // Mark OTP as used
        await pool.execute(
            'UPDATE email_verifications SET is_used = TRUE WHERE id = ?',
            [verification.id]
        );
        
        // Update user verification status
        await pool.execute(
            'UPDATE users SET is_verified = TRUE WHERE email = ?',
            [email]
        );
        
        res.json({ 
            success: true, 
            message: 'Email verified successfully' 
        });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Verification failed',
            code: 'VERIFICATION_FAILED'
        });
    }
});

app.post('/api/auth/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email is required',
                code: 'MISSING_EMAIL'
            });
        }
        
        // Check if user exists and not verified
        const [users] = await pool.execute(
            'SELECT id, full_name, is_verified FROM users WHERE email = ?',
            [email]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        const user = users[0];
        
        if (user.is_verified) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email already verified',
                code: 'ALREADY_VERIFIED'
            });
        }
        
        // Generate new OTP
        const otp = generateOTP();
        
        // Delete old OTPs
        await pool.execute(
            'DELETE FROM email_verifications WHERE email = ? AND is_used = FALSE',
            [email]
        );
        
        // Insert new OTP
        await pool.execute(
            'INSERT INTO email_verifications (user_id, email, otp_code, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
            [user.id, email, otp]
        );
        
        // Send verification email
        try {
            await transporter.sendMail({
                from: `"FriendsConnect" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: 'Verify Your FriendsConnect Account',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #6366f1;">Verification Code</h2>
                        <p>Hello ${user.full_name},</p>
                        <p>Your new verification code is:</p>
                        <div style="background: #f3f4f6; padding: 20px; text-align: center; font-size: 32px; letter-spacing: 5px; margin: 20px 0; border-radius: 8px;">
                            <strong>${otp}</strong>
                        </div>
                        <p>This code will expire in 10 minutes.</p>
                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                        <p style="color: #6b7280; font-size: 12px;">This is an automated message, please do not reply.</p>
                    </div>
                `
            });
        } catch (emailError) {
            console.error('Email sending failed:', emailError);
        }
        
        res.json({ 
            success: true, 
            message: 'Verification code sent successfully' 
        });
    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to resend verification',
            code: 'RESEND_FAILED'
        });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email is required',
                code: 'MISSING_EMAIL'
            });
        }
        
        const [users] = await pool.execute('SELECT id, full_name FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Email not found',
                code: 'EMAIL_NOT_FOUND'
            });
        }
        
        const user = users[0];
        const token = generateToken();
        
        // Delete old reset tokens
        await pool.execute(
            'DELETE FROM password_resets WHERE user_id = ? AND is_used = FALSE',
            [user.id]
        );
        
        // Insert new reset token
        await pool.execute(
            'INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))',
            [user.id, token]
        );
        
        const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
        
        // Send reset email
        try {
            await transporter.sendMail({
                from: `"FriendsConnect" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: 'Reset Your FriendsConnect Password',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #6366f1;">Password Reset Request</h2>
                        <p>Hello ${user.full_name},</p>
                        <p>Click the button below to reset your password:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${resetLink}" style="background: #6366f1; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
                                Reset Password
                            </a>
                        </div>
                        <p>Or copy and paste this link in your browser:</p>
                        <p style="background: #f3f4f6; padding: 10px; border-radius: 4px; word-break: break-all;">
                            ${resetLink}
                        </p>
                        <p>This link will expire in 1 hour.</p>
                        <p>If you didn't request a password reset, you can safely ignore this email.</p>
                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                        <p style="color: #6b7280; font-size: 12px;">This is an automated message, please do not reply.</p>
                    </div>
                `
            });
        } catch (emailError) {
            console.error('Email sending failed:', emailError);
        }
        
        res.json({ 
            success: true, 
            message: 'Password reset email sent' 
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Password reset failed',
            code: 'RESET_FAILED'
        });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        if (!token || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                error: 'Token and new password are required',
                code: 'MISSING_DATA'
            });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ 
                success: false, 
                error: 'Password must be at least 6 characters',
                code: 'PASSWORD_TOO_SHORT'
            });
        }
        
        const [resets] = await pool.execute(
            'SELECT * FROM password_resets WHERE token = ? AND is_used = FALSE AND expires_at > NOW()',
            [token]
        );
        
        if (resets.length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid or expired token',
                code: 'INVALID_TOKEN'
            });
        }
        
        const reset = resets[0];
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update password
        await pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [hashedPassword, reset.user_id]);
        
        // Mark token as used
        await pool.execute('UPDATE password_resets SET is_used = TRUE WHERE id = ?', [reset.id]);
        
        // Invalidate all sessions
        await pool.execute('DELETE FROM sessions WHERE user_id = ?', [reset.user_id]);
        
        res.json({ 
            success: true, 
            message: 'Password reset successful' 
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Password reset failed',
            code: 'RESET_FAILED'
        });
    }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (token) {
            const decoded = jwt.verify(token, JWT_SECRET);
            
            // Delete session
            await pool.execute(
                'DELETE FROM sessions WHERE user_id = ? AND session_token = ?',
                [req.user.id, decoded.sessionToken]
            );
            
            // Update online status
            await pool.execute(
                'UPDATE users SET is_online = FALSE, last_seen = NOW() WHERE id = ?',
                [req.user.id]
            );
            
            // Update login history
            await pool.execute(
                'UPDATE login_history SET logout_time = NOW() WHERE user_id = ? AND logout_time IS NULL ORDER BY login_time DESC LIMIT 1',
                [req.user.id]
            );
        }
        
        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Logout failed',
            code: 'LOGOUT_FAILED'
        });
    }
});

// 2. USER PROFILE ROUTES
app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const [user] = await pool.execute(
            `SELECT id, username, email, full_name, bio, profile_pic, cover_pic, 
                    birthdate, gender, phone, country, city, is_verified, 
                    is_online, last_seen, privacy_level, friend_privacy, 
                    theme_preference, created_at
             FROM users WHERE id = ?`,
            [req.user.id]
        );
        
        // Get friend count
        const [friendCount] = await pool.execute(
            `SELECT COUNT(*) as count FROM friendships 
             WHERE user1_id = ? OR user2_id = ?`,
            [req.user.id, req.user.id]
        );
        
        // Get post count
        const [postCount] = await pool.execute(
            'SELECT COUNT(*) as count FROM posts WHERE user_id = ? AND is_deleted = FALSE',
            [req.user.id]
        );
        
        res.json({
            success: true,
            data: {
                ...user[0],
                friend_count: friendCount[0].count,
                post_count: postCount[0].count
            }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch user data',
            code: 'USER_FETCH_FAILED'
        });
    }
});

app.put('/api/users/me', authenticateToken, upload.fields([
    { name: 'profile_pic', maxCount: 1 },
    { name: 'cover_pic', maxCount: 1 }
]), async (req, res) => {
    try {
        const updates = req.body;
        const updateFields = [];
        const values = [];
        
        // Handle file uploads
        if (req.files?.profile_pic) {
            updates.profile_pic = `/uploads/profiles/${req.files.profile_pic[0].filename}`;
        }
        if (req.files?.cover_pic) {
            updates.cover_pic = `/uploads/covers/${req.files.cover_pic[0].filename}`;
        }
        
        // Build dynamic update query
        Object.keys(updates).forEach(key => {
            if (updates[key] !== undefined && updates[key] !== null && updates[key] !== '') {
                updateFields.push(`${key} = ?`);
                values.push(updates[key]);
            }
        });
        
        if (updateFields.length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'No updates provided',
                code: 'NO_UPDATES'
            });
        }
        
        values.push(req.user.id);
        
        const query = `UPDATE users SET ${updateFields.join(', ')}, updated_at = NOW() WHERE id = ?`;
        await pool.execute(query, values);
        
        // Get updated user data
        const [user] = await pool.execute(
            'SELECT id, username, email, full_name, profile_pic, cover_pic, bio FROM users WHERE id = ?',
            [req.user.id]
        );
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: user[0]
        });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update profile',
            code: 'PROFILE_UPDATE_FAILED'
        });
    }
});

app.get('/api/users/:username', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.execute(
            `SELECT id, username, full_name, bio, profile_pic, cover_pic, 
                    is_verified, is_online, last_seen, privacy_level, 
                    created_at FROM users WHERE username = ?`,
            [req.params.username]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        const user = users[0];
        
        // Check privacy
        if (user.privacy_level === 'private' && user.id !== req.user.id) {
            // Check if they're friends
            const [friendship] = await pool.execute(
                `SELECT 1 FROM friendships 
                 WHERE (user1_id = ? AND user2_id = ?) 
                    OR (user1_id = ? AND user2_id = ?)`,
                [req.user.id, user.id, user.id, req.user.id]
            );
            
            if (friendship.length === 0) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'Profile is private',
                    code: 'PRIVATE_PROFILE'
                });
            }
        }
        
        // Get additional data
        const [friendCount] = await pool.execute(
            `SELECT COUNT(*) as count FROM friendships 
             WHERE user1_id = ? OR user2_id = ?`,
            [user.id, user.id]
        );
        
        const [postCount] = await pool.execute(
            'SELECT COUNT(*) as count FROM posts WHERE user_id = ? AND is_deleted = FALSE AND privacy != "only_me"',
            [user.id]
        );
        
        // Check friendship status
        let friendshipStatus = 'none';
        let friendRequestId = null;
        
        if (user.id !== req.user.id) {
            const [friendRequest] = await pool.execute(
                'SELECT id, status FROM friend_requests WHERE sender_id = ? AND receiver_id = ? OR sender_id = ? AND receiver_id = ?',
                [req.user.id, user.id, user.id, req.user.id]
            );
            
            if (friendRequest.length > 0) {
                friendshipStatus = friendRequest[0].status;
                friendRequestId = friendRequest[0].id;
            } else {
                const [friendship] = await pool.execute(
                    `SELECT 1 FROM friendships 
                     WHERE (user1_id = ? AND user2_id = ?) 
                        OR (user1_id = ? AND user2_id = ?)`,
                    [req.user.id, user.id, user.id, req.user.id]
                );
                
                if (friendship.length > 0) {
                    friendshipStatus = 'friends';
                }
            }
        }
        
        // Get mutual friends
        const [mutualFriends] = await pool.execute(
            `SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online 
             FROM friendships f1
             JOIN friendships f2 ON f1.user2_id = f2.user2_id
             JOIN users u ON f1.user2_id = u.id
             WHERE f1.user1_id = ? AND f2.user1_id = ? AND u.id NOT IN (?, ?)
             UNION
             SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online 
             FROM friendships f1
             JOIN friendships f2 ON f1.user2_id = f2.user1_id
             JOIN users u ON f1.user2_id = u.id
             WHERE f1.user1_id = ? AND f2.user2_id = ? AND u.id NOT IN (?, ?)`,
            [req.user.id, user.id, req.user.id, user.id, req.user.id, user.id, req.user.id, user.id]
        );
        
        res.json({
            success: true,
            data: {
                ...user,
                friend_count: friendCount[0].count,
                post_count: postCount[0].count,
                friendship_status: friendshipStatus,
                friend_request_id: friendRequestId,
                mutual_friends: mutualFriends
            }
        });
    } catch (error) {
        console.error('Get user profile error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch user profile',
            code: 'PROFILE_FETCH_FAILED'
        });
    }
});

app.get('/api/users/search/:query', authenticateToken, async (req, res) => {
    try {
        const query = `%${req.params.query}%`;
        const limit = parseInt(req.query.limit) || 20;
        const offset = parseInt(req.query.offset) || 0;
        
        const [users] = await pool.execute(
            `SELECT id, username, full_name, profile_pic, is_verified, is_online, 
                    (SELECT COUNT(*) FROM friendships 
                     WHERE (user1_id = users.id AND user2_id = ?) 
                        OR (user1_id = ? AND user2_id = users.id)) as is_friend
             FROM users 
             WHERE (username LIKE ? OR full_name LIKE ?) 
                AND id != ? 
                AND account_status = 'active'
             LIMIT ? OFFSET ?`,
            [req.user.id, req.user.id, query, query, req.user.id, limit, offset]
        );
        
        res.json({
            success: true,
            data: users,
            pagination: {
                limit,
                offset,
                hasMore: users.length === limit
            }
        });
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Search failed',
            code: 'SEARCH_FAILED'
        });
    }
});

// 3. FRIEND SYSTEM ROUTES
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    try {
        const { receiver_id } = req.body;
        
        if (!receiver_id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Receiver ID is required',
                code: 'MISSING_RECEIVER_ID'
            });
        }
        
        if (receiver_id === req.user.id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Cannot send friend request to yourself',
                code: 'SELF_REQUEST'
            });
        }
        
        // Check if receiver exists
        const [users] = await pool.execute(
            'SELECT id, username, full_name, friend_privacy FROM users WHERE id = ? AND account_status = "active"',
            [receiver_id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        const receiver = users[0];
        
        // Check friend privacy
        if (receiver.friend_privacy === 'no_one') {
            return res.status(403).json({ 
                success: false, 
                error: 'User is not accepting friend requests',
                code: 'FRIEND_PRIVACY_RESTRICTED'
            });
        }
        
        if (receiver.friend_privacy === 'friends_of_friends') {
            const [mutual] = await pool.execute(
                `SELECT 1 FROM friendships f1
                 JOIN friendships f2 ON f1.user2_id = f2.user2_id
                 WHERE f1.user1_id = ? AND f2.user1_id = ?`,
                [req.user.id, receiver_id]
            );
            
            if (mutual.length === 0) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'You must have mutual friends to send request',
                    code: 'NO_MUTUAL_FRIENDS'
                });
            }
        }
        
        // Check if already friends
        const [existingFriendship] = await pool.execute(
            `SELECT 1 FROM friendships 
             WHERE (user1_id = ? AND user2_id = ?) 
                OR (user1_id = ? AND user2_id = ?)`,
            [req.user.id, receiver_id, receiver_id, req.user.id]
        );
        
        if (existingFriendship.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Already friends',
                code: 'ALREADY_FRIENDS'
            });
        }
        
        // Check for existing request
        const [existingRequest] = await pool.execute(
            'SELECT id, status FROM friend_requests WHERE sender_id = ? AND receiver_id = ?',
            [req.user.id, receiver_id]
        );
        
        if (existingRequest.length > 0) {
            const request = existingRequest[0];
            if (request.status === 'pending') {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Friend request already sent',
                    code: 'REQUEST_ALREADY_SENT'
                });
            } else if (request.status === 'rejected') {
                // Update existing request to pending
                await pool.execute(
                    'UPDATE friend_requests SET status = "pending", created_at = NOW() WHERE id = ?',
                    [request.id]
                );
            }
        } else {
            // Check if blocked
            const [blocked] = await pool.execute(
                'SELECT 1 FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?',
                [receiver_id, req.user.id]
            );
            
            if (blocked.length > 0) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'You are blocked by this user',
                    code: 'BLOCKED_BY_USER'
                });
            }
            
            // Create friend request
            await pool.execute(
                'INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)',
                [req.user.id, receiver_id]
            );
        }
        
        // Create notification
        await pool.execute(
            `INSERT INTO notifications (user_id, type, sender_id, content) 
             VALUES (?, 'friend_request', ?, ?)`,
            [receiver_id, req.user.id, `${req.user.full_name} sent you a friend request`]
        );
        
        // Emit socket event
        const receiverSocketId = onlineUsers.get(receiver_id);
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('new_notification', {
                type: 'friend_request',
                senderId: req.user.id,
                senderName: req.user.full_name,
                senderProfilePic: req.user.profile_pic
            });
        }
        
        res.status(201).json({
            success: true,
            message: 'Friend request sent'
        });
    } catch (error) {
        console.error('Send friend request error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to send friend request',
            code: 'FRIEND_REQUEST_FAILED'
        });
    }
});

app.post('/api/friends/request/:requestId/respond', authenticateToken, async (req, res) => {
    try {
        const { requestId } = req.params;
        const { action } = req.body; // 'accept' or 'reject'
        
        if (!['accept', 'reject'].includes(action)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid action. Must be "accept" or "reject"',
                code: 'INVALID_ACTION'
            });
        }
        
        // Get request
        const [requests] = await pool.execute(
            'SELECT * FROM friend_requests WHERE id = ? AND receiver_id = ? AND status = "pending"',
            [requestId, req.user.id]
        );
        
        if (requests.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Friend request not found',
                code: 'REQUEST_NOT_FOUND'
            });
        }
        
        const request = requests[0];
        
        if (action === 'accept') {
            // Create friendship
            await pool.execute(
                'INSERT INTO friendships (user1_id, user2_id) VALUES (?, ?)',
                [request.sender_id, request.receiver_id]
            );
            
            // Update request status
            await pool.execute(
                'UPDATE friend_requests SET status = "accepted" WHERE id = ?',
                [requestId]
            );
            
            // Create notification for sender
            await pool.execute(
                `INSERT INTO notifications (user_id, type, sender_id, content) 
                 VALUES (?, 'friend_accept', ?, ?)`,
                [request.sender_id, req.user.id, `${req.user.full_name} accepted your friend request`]
            );
            
            // Emit socket event to sender
            const senderSocketId = onlineUsers.get(request.sender_id);
            if (senderSocketId) {
                io.to(senderSocketId).emit('friend_request_accepted', {
                    userId: req.user.id,
                    userName: req.user.full_name,
                    userProfilePic: req.user.profile_pic
                });
            }
            
            res.json({ 
                success: true, 
                message: 'Friend request accepted' 
            });
        } else {
            // Update request status
            await pool.execute(
                'UPDATE friend_requests SET status = "rejected" WHERE id = ?',
                [requestId]
            );
            
            res.json({ 
                success: true, 
                message: 'Friend request rejected' 
            });
        }
    } catch (error) {
        console.error('Respond to friend request error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to respond to friend request',
            code: 'RESPOND_REQUEST_FAILED'
        });
    }
});

app.delete('/api/friends/remove/:friendId', authenticateToken, async (req, res) => {
    try {
        const { friendId } = req.params;
        
        // Check if friendship exists
        const [friendship] = await pool.execute(
            `SELECT 1 FROM friendships 
             WHERE (user1_id = ? AND user2_id = ?) 
                OR (user1_id = ? AND user2_id = ?)`,
            [req.user.id, friendId, friendId, req.user.id]
        );
        
        if (friendship.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Friendship not found',
                code: 'FRIENDSHIP_NOT_FOUND'
            });
        }
        
        // Remove friendship
        await pool.execute(
            `DELETE FROM friendships 
             WHERE (user1_id = ? AND user2_id = ?) 
                OR (user1_id = ? AND user2_id = ?)`,
            [req.user.id, friendId, friendId, req.user.id]
        );
        
        // Delete any pending friend requests
        await pool.execute(
            'DELETE FROM friend_requests WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)',
            [req.user.id, friendId, friendId, req.user.id]
        );
        
        res.json({ 
            success: true, 
            message: 'Friend removed successfully' 
        });
    } catch (error) {
        console.error('Remove friend error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to remove friend',
            code: 'REMOVE_FRIEND_FAILED'
        });
    }
});

app.post('/api/friends/block/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const { reason } = req.body;
        
        if (userId === req.user.id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Cannot block yourself',
                code: 'SELF_BLOCK'
            });
        }
        
        // Check if user exists
        const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        // Check if already blocked
        const [alreadyBlocked] = await pool.execute(
            'SELECT 1 FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?',
            [req.user.id, userId]
        );
        
        if (alreadyBlocked.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'User already blocked',
                code: 'ALREADY_BLOCKED'
            });
        }
        
        // Remove friendship if exists
        await pool.execute(
            `DELETE FROM friendships 
             WHERE (user1_id = ? AND user2_id = ?) 
                OR (user1_id = ? AND user2_id = ?)`,
            [req.user.id, userId, userId, req.user.id]
        );
        
        // Delete friend requests
        await pool.execute(
            'DELETE FROM friend_requests WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)',
            [req.user.id, userId, userId, req.user.id]
        );
        
        // Block user
        await pool.execute(
            'INSERT INTO blocked_users (blocker_id, blocked_id, reason) VALUES (?, ?, ?)',
            [req.user.id, userId, reason || 'No reason provided']
        );
        
        res.json({ 
            success: true, 
            message: 'User blocked successfully' 
        });
    } catch (error) {
        console.error('Block user error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to block user',
            code: 'BLOCK_USER_FAILED'
        });
    }
});

app.delete('/api/friends/unblock/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const [result] = await pool.execute(
            'DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?',
            [req.user.id, userId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not blocked',
                code: 'USER_NOT_BLOCKED'
            });
        }
        
        res.json({ 
            success: true, 
            message: 'User unblocked successfully' 
        });
    } catch (error) {
        console.error('Unblock user error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to unblock user',
            code: 'UNBLOCK_USER_FAILED'
        });
    }
});

app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        
        const [friends] = await pool.execute(
            `SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online, u.last_seen,
                    f.created_at as friends_since
             FROM friendships f
             JOIN users u ON (f.user1_id = u.id AND f.user2_id = ?) OR (f.user2_id = u.id AND f.user1_id = ?)
             WHERE u.id != ?
             ORDER BY u.is_online DESC, u.full_name ASC
             LIMIT ? OFFSET ?`,
            [req.user.id, req.user.id, req.user.id, limit, offset]
        );
        
        // Get total count
        const [countResult] = await pool.execute(
            `SELECT COUNT(*) as total
             FROM friendships f
             JOIN users u ON (f.user1_id = u.id AND f.user2_id = ?) OR (f.user2_id = u.id AND f.user1_id = ?)
             WHERE u.id != ?`,
            [req.user.id, req.user.id, req.user.id]
        );
        
        res.json({
            success: true,
            data: friends,
            pagination: {
                total: countResult[0].total,
                limit,
                offset,
                hasMore: offset + friends.length < countResult[0].total
            }
        });
    } catch (error) {
        console.error('Get friends error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch friends',
            code: 'FETCH_FRIENDS_FAILED'
        });
    }
});

app.get('/api/friends/pending', authenticateToken, async (req, res) => {
    try {
        const [requests] = await pool.execute(
            `SELECT fr.*, u.username, u.full_name, u.profile_pic, u.is_online 
             FROM friend_requests fr
             JOIN users u ON fr.sender_id = u.id
             WHERE fr.receiver_id = ? AND fr.status = 'pending'
             ORDER BY fr.created_at DESC`,
            [req.user.id]
        );
        
        res.json({
            success: true,
            data: requests
        });
    } catch (error) {
        console.error('Get pending requests error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch pending requests',
            code: 'FETCH_PENDING_FAILED'
        });
    }
});

app.get('/api/friends/mutual/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const [mutualFriends] = await pool.execute(
            `SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online 
             FROM friendships f1
             JOIN friendships f2 ON f1.user2_id = f2.user2_id
             JOIN users u ON f1.user2_id = u.id
             WHERE f1.user1_id = ? AND f2.user1_id = ? AND u.id NOT IN (?, ?)
             UNION
             SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online 
             FROM friendships f1
             JOIN friendships f2 ON f1.user2_id = f2.user1_id
             JOIN users u ON f1.user2_id = u.id
             WHERE f1.user1_id = ? AND f2.user2_id = ? AND u.id NOT IN (?, ?)`,
            [req.user.id, userId, req.user.id, userId, req.user.id, userId, req.user.id, userId]
        );
        
        res.json({
            success: true,
            data: mutualFriends
        });
    } catch (error) {
        console.error('Get mutual friends error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch mutual friends',
            code: 'FETCH_MUTUAL_FAILED'
        });
    }
});

// 4. POST SYSTEM ROUTES
app.post('/api/posts', authenticateToken, upload.array('post_media', 10), async (req, res) => {
    try {
        const { content, privacy, location, feeling, tagged_users } = req.body;
        
        if (!content && (!req.files || req.files.length === 0)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Post content or media is required',
                code: 'EMPTY_POST'
            });
        }
        
        // Start transaction
        const connection = await pool.getConnection();
        await connection.beginTransaction();
        
        try {
            // Create post
            const [postResult] = await connection.execute(
                `INSERT INTO posts (user_id, content, privacy, location, feeling, tagged_users, post_type) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [req.user.id, content || '', privacy || 'public', location || null, feeling || null,
                 tagged_users ? JSON.stringify(tagged_users.split(',')) : null, 'text']
            );
            
            const postId = postResult.insertId;
            let postType = 'text';
            
            // Handle media uploads
            if (req.files && req.files.length > 0) {
                const mediaValues = req.files.map((file, index) => [
                    postId,
                    `/uploads/posts/${file.filename}`,
                    isImage(file.mimetype) ? 'image' : isVideo(file.mimetype) ? 'video' : 'file',
                    isImage(file.mimetype) ? `/uploads/posts/${file.filename}` : null,
                    index
                ]);
                
                await connection.query(
                    'INSERT INTO post_media (post_id, media_url, media_type, thumbnail_url, order_index) VALUES ?',
                    [mediaValues]
                );
                
                // Update post type
                postType = req.files.length > 1 ? 'album' : 
                          isImage(req.files[0].mimetype) ? 'image' : 
                          isVideo(req.files[0].mimetype) ? 'video' : 'file';
                
                await connection.execute(
                    'UPDATE posts SET post_type = ? WHERE id = ?',
                    [postType, postId]
                );
            }
            
            await connection.commit();
            
            // Get complete post data
            const [posts] = await pool.execute(
                `SELECT p.*, u.username, u.full_name, u.profile_pic, u.is_verified,
                        (SELECT COUNT(*) FROM post_reactions WHERE post_id = p.id) as reaction_count,
                        (SELECT COUNT(*) FROM comments WHERE post_id = p.id AND parent_id IS NULL) as comment_count,
                        0 as share_count,
                        FALSE as has_reacted,
                        FALSE as is_saved
                 FROM posts p
                 JOIN users u ON p.user_id = u.id
                 WHERE p.id = ?`,
                [postId]
            );
            
            // Get media if exists
            let media = [];
            if (postType !== 'text') {
                const [mediaRows] = await pool.execute(
                    'SELECT * FROM post_media WHERE post_id = ? ORDER BY order_index',
                    [postId]
                );
                media = mediaRows;
            }
            
            res.status(201).json({
                success: true,
                message: 'Post created successfully',
                data: {
                    ...posts[0],
                    media
                }
            });
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Create post error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create post',
            code: 'CREATE_POST_FAILED'
        });
    }
});

app.get('/api/posts/feed', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        
        const [posts] = await pool.execute(
            `SELECT p.*, u.username, u.full_name, u.profile_pic, u.is_verified,
                    (SELECT COUNT(*) FROM post_reactions WHERE post_id = p.id) as reaction_count,
                    (SELECT COUNT(*) FROM comments WHERE post_id = p.id AND parent_id IS NULL) as comment_count,
                    (SELECT COUNT(*) FROM shares WHERE post_id = p.id) as share_count,
                    EXISTS(SELECT 1 FROM post_reactions WHERE post_id = p.id AND user_id = ?) as has_reacted,
                    EXISTS(SELECT 1 FROM saved_posts WHERE post_id = p.id AND user_id = ?) as is_saved
             FROM posts p
             JOIN users u ON p.user_id = u.id
             WHERE p.is_deleted = FALSE 
                AND (p.privacy = 'public' 
                     OR (p.privacy = 'friends' AND EXISTS(
                         SELECT 1 FROM friendships 
                         WHERE (user1_id = ? AND user2_id = p.user_id) 
                            OR (user1_id = p.user_id AND user2_id = ?)
                     ))
                     OR p.user_id = ?)
             ORDER BY p.created_at DESC
             LIMIT ? OFFSET ?`,
            [req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, limit, offset]
        );
        
        // Get media for each post
        for (let post of posts) {
            if (post.post_type !== 'text') {
                const [media] = await pool.execute(
                    'SELECT * FROM post_media WHERE post_id = ? ORDER BY order_index',
                    [post.id]
                );
                post.media = media;
            }
            
            // Get reactions breakdown
            const [reactions] = await pool.execute(
                `SELECT reaction_type, COUNT(*) as count 
                 FROM post_reactions 
                 WHERE post_id = ? 
                 GROUP BY reaction_type`,
                [post.id]
            );
            post.reactions_breakdown = reactions;
        }
        
        // Get total count for pagination
        const [countResult] = await pool.execute(
            `SELECT COUNT(*) as total
             FROM posts p
             WHERE p.is_deleted = FALSE 
                AND (p.privacy = 'public' 
                     OR (p.privacy = 'friends' AND EXISTS(
                         SELECT 1 FROM friendships 
                         WHERE (user1_id = ? AND user2_id = p.user_id) 
                            OR (user1_id = p.user_id AND user2_id = ?)
                     ))
                     OR p.user_id = ?)`,
            [req.user.id, req.user.id, req.user.id]
        );
        
        res.json({
            success: true,
            data: posts,
            pagination: {
                total: countResult[0].total,
                page,
                limit,
                totalPages: Math.ceil(countResult[0].total / limit),
                hasMore: offset + posts.length < countResult[0].total
            }
        });
    } catch (error) {
        console.error('Get feed error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch feed',
            code: 'FETCH_FEED_FAILED'
        });
    }
});

app.get('/api/posts/:postId', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        
        const [posts] = await pool.execute(
            `SELECT p.*, u.username, u.full_name, u.profile_pic, u.is_verified,
                    (SELECT COUNT(*) FROM post_reactions WHERE post_id = p.id) as reaction_count,
                    (SELECT COUNT(*) FROM comments WHERE post_id = p.id AND parent_id IS NULL) as comment_count,
                    (SELECT COUNT(*) FROM shares WHERE post_id = p.id) as share_count,
                    EXISTS(SELECT 1 FROM post_reactions WHERE post_id = p.id AND user_id = ?) as has_reacted,
                    EXISTS(SELECT 1 FROM saved_posts WHERE post_id = p.id AND user_id = ?) as is_saved
             FROM posts p
             JOIN users u ON p.user_id = u.id
             WHERE p.id = ? AND p.is_deleted = FALSE`,
            [req.user.id, req.user.id, postId]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Post not found',
                code: 'POST_NOT_FOUND'
            });
        }
        
        const post = posts[0];
        
        // Check privacy
        if (post.user_id !== req.user.id && post.privacy !== 'public') {
            if (post.privacy === 'only_me') {
                return res.status(403).json({ 
                    success: false, 
                    error: 'Post is private',
                    code: 'PRIVATE_POST'
                });
            }
            
            if (post.privacy === 'friends') {
                const [friendship] = await pool.execute(
                    `SELECT 1 FROM friendships 
                     WHERE (user1_id = ? AND user2_id = ?) 
                        OR (user1_id = ? AND user2_id = ?)`,
                    [req.user.id, post.user_id, post.user_id, req.user.id]
                );
                
                if (friendship.length === 0) {
                    return res.status(403).json({ 
                        success: false, 
                        error: 'You must be friends to view this post',
                        code: 'NOT_FRIENDS'
                    });
                }
            }
        }
        
        // Get media
        let media = [];
        if (post.post_type !== 'text') {
            const [mediaRows] = await pool.execute(
                'SELECT * FROM post_media WHERE post_id = ? ORDER BY order_index',
                [postId]
            );
            media = mediaRows;
        }
        
        // Get reactions
        const [reactions] = await pool.execute(
            `SELECT pr.*, u.username, u.full_name, u.profile_pic 
             FROM post_reactions pr
             JOIN users u ON pr.user_id = u.id
             WHERE pr.post_id = ?
             ORDER BY pr.created_at DESC
             LIMIT 50`,
            [postId]
        );
        
        // Get reactions breakdown
        const [reactionsBreakdown] = await pool.execute(
            `SELECT reaction_type, COUNT(*) as count 
             FROM post_reactions 
             WHERE post_id = ? 
             GROUP BY reaction_type`,
            [postId]
        );
        
        // Get comments
        const [comments] = await pool.execute(
            `SELECT c.*, u.username, u.full_name, u.profile_pic,
                    (SELECT COUNT(*) FROM comment_reactions WHERE comment_id = c.id) as reaction_count
             FROM comments c
             JOIN users u ON c.user_id = u.id
             WHERE c.post_id = ? AND c.parent_id IS NULL AND c.is_deleted = FALSE
             ORDER BY c.created_at DESC
             LIMIT 100`,
            [postId]
        );
        
        res.json({
            success: true,
            data: {
                ...post,
                media,
                reactions,
                reactions_breakdown: reactionsBreakdown,
                comments
            }
        });
    } catch (error) {
        console.error('Get post error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch post',
            code: 'FETCH_POST_FAILED'
        });
    }
});

app.post('/api/posts/:postId/react', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        const { reaction_type = 'like' } = req.body;
        
        const validReactions = ['like', 'love', 'haha', 'wow', 'sad', 'angry'];
        if (!validReactions.includes(reaction_type)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid reaction type',
                code: 'INVALID_REACTION'
            });
        }
        
        // Check if post exists and user can react
        const [posts] = await pool.execute(
            `SELECT p.*, u.id as user_id FROM posts p
             JOIN users u ON p.user_id = u.id
             WHERE p.id = ? AND p.is_deleted = FALSE`,
            [postId]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Post not found',
                code: 'POST_NOT_FOUND'
            });
        }
        
        const post = posts[0];
        
        // Check privacy
        if (post.user_id !== req.user.id && post.privacy !== 'public') {
            if (post.privacy === 'friends') {
                const [friendship] = await pool.execute(
                    `SELECT 1 FROM friendships 
                     WHERE (user1_id = ? AND user2_id = ?) 
                        OR (user1_id = ? AND user2_id = ?)`,
                    [req.user.id, post.user_id, post.user_id, req.user.id]
                );
                
                if (friendship.length === 0) {
                    return res.status(403).json({ 
                        success: false, 
                        error: 'Cannot react to this post',
                        code: 'REACTION_NOT_ALLOWED'
                    });
                }
            }
        }
        
        // Check if already reacted
        const [existing] = await pool.execute(
            'SELECT id, reaction_type FROM post_reactions WHERE post_id = ? AND user_id = ?',
            [postId, req.user.id]
        );
        
        if (existing.length > 0) {
            const existingReaction = existing[0];
            
            if (existingReaction.reaction_type === reaction_type) {
                // Remove reaction if same type
                await pool.execute('DELETE FROM post_reactions WHERE id = ?', [existingReaction.id]);
                
                res.json({
                    success: true,
                    message: 'Reaction removed',
                    action: 'removed'
                });
            } else {
                // Update reaction
                await pool.execute(
                    'UPDATE post_reactions SET reaction_type = ? WHERE id = ?',
                    [reaction_type, existingReaction.id]
                );
                
                res.json({
                    success: true,
                    message: 'Reaction updated',
                    action: 'updated'
                });
            }
        } else {
            // Create new reaction
            await pool.execute(
                'INSERT INTO post_reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)',
                [postId, req.user.id, reaction_type]
            );
            
            // Create notification (if not reacting to own post)
            if (post.user_id !== req.user.id) {
                await pool.execute(
                    `INSERT INTO notifications (user_id, type, sender_id, post_id, content) 
                     VALUES (?, 'like', ?, ?, ?)`,
                    [post.user_id, req.user.id, postId, 
                     `${req.user.full_name} reacted to your post`]
                );
                
                // Emit socket event
                const postOwnerSocketId = onlineUsers.get(post.user_id);
                if (postOwnerSocketId) {
                    io.to(postOwnerSocketId).emit('post_reacted', {
                        postId,
                        userId: req.user.id,
                        userName: req.user.full_name,
                        reactionType: reaction_type
                    });
                }
            }
            
            res.json({
                success: true,
                message: 'Reaction added',
                action: 'added'
            });
        }
    } catch (error) {
        console.error('React to post error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to react to post',
            code: 'REACTION_FAILED'
        });
    }
});

app.post('/api/posts/:postId/comment', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        const { content, parent_id } = req.body;
        
        if (!content || content.trim().length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Comment content is required',
                code: 'EMPTY_COMMENT'
            });
        }
        
        // Check if post exists
        const [posts] = await pool.execute(
            'SELECT user_id FROM posts WHERE id = ? AND is_deleted = FALSE',
            [postId]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Post not found',
                code: 'POST_NOT_FOUND'
            });
        }
        
        const post = posts[0];
        
        // Check if user can comment
        if (post.user_id !== req.user.id) {
            const [postPrivacy] = await pool.execute(
                'SELECT privacy FROM posts WHERE id = ?',
                [postId]
            );
            
            if (postPrivacy[0].privacy === 'friends') {
                const [friendship] = await pool.execute(
                    `SELECT 1 FROM friendships 
                     WHERE (user1_id = ? AND user2_id = ?) 
                        OR (user1_id = ? AND user2_id = ?)`,
                    [req.user.id, post.user_id, post.user_id, req.user.id]
                );
                
                if (friendship.length === 0) {
                    return res.status(403).json({ 
                        success: false, 
                        error: 'Cannot comment on this post',
                        code: 'COMMENT_NOT_ALLOWED'
                    });
                }
            } else if (postPrivacy[0].privacy === 'only_me') {
                return res.status(403).json({ 
                    success: false, 
                    error: 'Cannot comment on this post',
                    code: 'COMMENT_NOT_ALLOWED'
                });
            }
        }
        
        // Create comment
        const [result] = await pool.execute(
            'INSERT INTO comments (post_id, user_id, content, parent_id) VALUES (?, ?, ?, ?)',
            [postId, req.user.id, content.trim(), parent_id || null]
        );
        
        // Create notification (if not commenting on own post)
        if (post.user_id !== req.user.id) {
            await pool.execute(
                `INSERT INTO notifications (user_id, type, sender_id, post_id, comment_id, content) 
                 VALUES (?, 'comment', ?, ?, ?, ?)`,
                [post.user_id, req.user.id, postId, result.insertId,
                 `${req.user.full_name} commented on your post`]
            );
            
            // Emit socket event
            const postOwnerSocketId = onlineUsers.get(post.user_id);
            if (postOwnerSocketId) {
                io.to(postOwnerSocketId).emit('new_comment', {
                    postId,
                    userId: req.user.id,
                    userName: req.user.full_name,
                    commentId: result.insertId
                });
            }
        }
        
        // Get comment data
        const [comments] = await pool.execute(
            `SELECT c.*, u.username, u.full_name, u.profile_pic 
             FROM comments c
             JOIN users u ON c.user_id = u.id
             WHERE c.id = ?`,
            [result.insertId]
        );
        
        res.status(201).json({
            success: true,
            message: 'Comment added successfully',
            data: comments[0]
        });
    } catch (error) {
        console.error('Add comment error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to add comment',
            code: 'ADD_COMMENT_FAILED'
        });
    }
});

app.post('/api/posts/:postId/share', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        const { content } = req.body;
        
        // Check if post exists
        const [posts] = await pool.execute(
            'SELECT * FROM posts WHERE id = ? AND is_deleted = FALSE',
            [postId]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Post not found',
                code: 'POST_NOT_FOUND'
            });
        }
        
        const post = posts[0];
        
        // Check if user can share
        if (post.user_id !== req.user.id && post.privacy === 'only_me') {
            return res.status(403).json({ 
                success: false, 
                error: 'Cannot share this post',
                code: 'SHARE_NOT_ALLOWED'
            });
        }
        
        // Create share
        const [result] = await pool.execute(
            'INSERT INTO shares (post_id, user_id, content) VALUES (?, ?, ?)',
            [postId, req.user.id, content || '']
        );
        
        // Create notification (if not sharing own post)
        if (post.user_id !== req.user.id) {
            await pool.execute(
                `INSERT INTO notifications (user_id, type, sender_id, post_id, content) 
                 VALUES (?, 'share', ?, ?, ?)`,
                [post.user_id, req.user.id, postId, `${req.user.full_name} shared your post`]
            );
            
            // Emit socket event
            const postOwnerSocketId = onlineUsers.get(post.user_id);
            if (postOwnerSocketId) {
                io.to(postOwnerSocketId).emit('post_shared', {
                    postId,
                    userId: req.user.id,
                    userName: req.user.full_name
                });
            }
        }
        
        // Create a new post for the share
        const [sharePost] = await pool.execute(
            `INSERT INTO posts (user_id, content, privacy, post_type, original_post_id) 
             VALUES (?, ?, 'public', 'share', ?)`,
            [req.user.id, content || 'Shared a post', postId]
        );
        
        res.status(201).json({
            success: true,
            message: 'Post shared successfully',
            data: {
                shareId: result.insertId,
                postId: sharePost.insertId
            }
        });
    } catch (error) {
        console.error('Share post error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to share post',
            code: 'SHARE_POST_FAILED'
        });
    }
});

app.post('/api/posts/:postId/save', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        const { folder = 'general' } = req.body;
        
        // Check if post exists
        const [posts] = await pool.execute(
            'SELECT 1 FROM posts WHERE id = ? AND is_deleted = FALSE',
            [postId]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Post not found',
                code: 'POST_NOT_FOUND'
            });
        }
        
        // Check if already saved
        const [existing] = await pool.execute(
            'SELECT id FROM saved_posts WHERE user_id = ? AND post_id = ?',
            [req.user.id, postId]
        );
        
        if (existing.length > 0) {
            // Unsave
            await pool.execute(
                'DELETE FROM saved_posts WHERE id = ?',
                [existing[0].id]
            );
            
            res.json({
                success: true,
                message: 'Post unsaved successfully',
                action: 'unsaved'
            });
        } else {
            // Save post
            await pool.execute(
                'INSERT INTO saved_posts (user_id, post_id, folder) VALUES (?, ?, ?)',
                [req.user.id, postId, folder]
            );
            
            res.json({
                success: true,
                message: 'Post saved successfully',
                action: 'saved'
            });
        }
    } catch (error) {
        console.error('Save post error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to save post',
            code: 'SAVE_POST_FAILED'
        });
    }
});

app.delete('/api/posts/:postId', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        
        // Check if user owns the post
        const [posts] = await pool.execute(
            'SELECT user_id FROM posts WHERE id = ?',
            [postId]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Post not found',
                code: 'POST_NOT_FOUND'
            });
        }
        
        if (posts[0].user_id !== req.user.id) {
            return res.status(403).json({ 
                success: false, 
                error: 'Not authorized to delete this post',
                code: 'UNAUTHORIZED'
            });
        }
        
        // Soft delete
        await pool.execute(
            'UPDATE posts SET is_deleted = TRUE WHERE id = ?',
            [postId]
        );
        
        res.json({ 
            success: true, 
            message: 'Post deleted successfully' 
        });
    } catch (error) {
        console.error('Delete post error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete post',
            code: 'DELETE_POST_FAILED'
        });
    }
});

// 5. CHAT & MESSAGING ROUTES
app.get('/api/conversations', authenticateToken, async (req, res) => {
    try {
        const [conversations] = await pool.execute(
            `SELECT DISTINCT c.*, 
                    m.content as last_message,
                    m.created_at as last_message_time,
                    m.sender_id as last_sender_id,
                    (SELECT COUNT(*) FROM messages m2 
                     LEFT JOIN message_reads mr ON m2.id = mr.message_id AND mr.user_id = ?
                     WHERE m2.conversation_id = c.id AND m2.sender_id != ? AND mr.id IS NULL) as unread_count
             FROM conversations c
             JOIN conversation_participants cp ON c.id = cp.conversation_id
             LEFT JOIN messages m ON m.id = (
                 SELECT id FROM messages 
                 WHERE conversation_id = c.id 
                 ORDER BY created_at DESC LIMIT 1
             )
             WHERE cp.user_id = ? AND cp.left_at IS NULL
             ORDER BY last_message_time DESC NULLS LAST`,
            [req.user.id, req.user.id, req.user.id]
        );
        
        // Get participants for each conversation
        for (let conv of conversations) {
            const [participants] = await pool.execute(
                `SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online, u.last_seen, cp.role
                 FROM conversation_participants cp
                 JOIN users u ON cp.user_id = u.id
                 WHERE cp.conversation_id = ? AND cp.left_at IS NULL`,
                [conv.id]
            );
            conv.participants = participants;
            
            // Get typing status
            const [typing] = await pool.execute(
                `SELECT u.id, u.username, u.full_name 
                 FROM typing_indicators ti
                 JOIN users u ON ti.user_id = u.id
                 WHERE ti.conversation_id = ? AND ti.is_typing = TRUE AND ti.user_id != ?`,
                [conv.id, req.user.id]
            );
            conv.typing = typing;
        }
        
        res.json({
            success: true,
            data: conversations
        });
    } catch (error) {
        console.error('Get conversations error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch conversations',
            code: 'FETCH_CONVERSATIONS_FAILED'
        });
    }
});

app.post('/api/conversations/private', authenticateToken, async (req, res) => {
    try {
        const { other_user_id } = req.body;
        
        if (!other_user_id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Other user ID is required',
                code: 'MISSING_USER_ID'
            });
        }
        
        if (other_user_id === req.user.id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Cannot create conversation with yourself',
                code: 'SELF_CONVERSATION'
            });
        }
        
        // Check if other user exists
        const [users] = await pool.execute(
            'SELECT id FROM users WHERE id = ? AND account_status = "active"',
            [other_user_id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        // Check if conversation already exists
        const [existing] = await pool.execute(
            `SELECT c.id FROM conversations c
             JOIN conversation_participants cp1 ON c.id = cp1.conversation_id
             JOIN conversation_participants cp2 ON c.id = cp2.conversation_id
             WHERE c.conversation_type = 'private'
               AND cp1.user_id = ? AND cp2.user_id = ?
               AND cp1.left_at IS NULL AND cp2.left_at IS NULL`,
            [req.user.id, other_user_id]
        );
        
        if (existing.length > 0) {
            return res.json({ 
                success: true, 
                data: { conversationId: existing[0].id } 
            });
        }
        
        // Create new conversation
        const connection = await pool.getConnection();
        await connection.beginTransaction();
        
        try {
            const [convResult] = await connection.execute(
                'INSERT INTO conversations (conversation_type) VALUES ("private")',
                []
            );
            
            const conversationId = convResult.insertId;
            
            // Add participants
            await connection.execute(
                'INSERT INTO conversation_participants (conversation_id, user_id) VALUES (?, ?), (?, ?)',
                [conversationId, req.user.id, conversationId, other_user_id]
            );
            
            await connection.commit();
            
            res.status(201).json({
                success: true,
                data: { conversationId }
            });
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Create conversation error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create conversation',
            code: 'CREATE_CONVERSATION_FAILED'
        });
    }
});

app.get('/api/conversations/:conversationId/messages', authenticateToken, async (req, res) => {
    try {
        const { conversationId } = req.params;
        const limit = parseInt(req.query.limit) || 50;
        const before = req.query.before ? parseInt(req.query.before) : null;
        
        // Check if user is participant
        const [participants] = await pool.execute(
            'SELECT 1 FROM conversation_participants WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL',
            [conversationId, req.user.id]
        );
        
        if (participants.length === 0) {
            return res.status(403).json({ 
                success: false, 
                error: 'Not a participant',
                code: 'NOT_PARTICIPANT'
            });
        }
        
        let query = `
            SELECT m.*, u.username, u.full_name, u.profile_pic,
                   (SELECT COUNT(*) FROM message_reads WHERE message_id = m.id) as read_count,
                   EXISTS(SELECT 1 FROM message_reads WHERE message_id = m.id AND user_id = ?) as is_read_by_me
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.conversation_id = ? AND m.is_deleted = FALSE
        `;
        
        const params = [req.user.id, conversationId];
        
        if (before) {
            query += ' AND m.id < ?';
            params.push(before);
        }
        
        query += ' ORDER BY m.created_at DESC LIMIT ?';
        params.push(limit);
        
        const [messages] = await pool.execute(query, params);
        
        // Mark messages as read
        await pool.execute(
            `INSERT INTO message_reads (message_id, user_id)
             SELECT m.id, ? FROM messages m
             LEFT JOIN message_reads mr ON m.id = mr.message_id AND mr.user_id = ?
             WHERE m.conversation_id = ? AND m.sender_id != ? AND mr.id IS NULL
             ON DUPLICATE KEY UPDATE read_at = NOW()`,
            [req.user.id, req.user.id, conversationId, req.user.id]
        );
        
        res.json({
            success: true,
            data: messages.reverse()
        });
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch messages',
            code: 'FETCH_MESSAGES_FAILED'
        });
    }
});

app.post('/api/conversations/:conversationId/messages', authenticateToken, upload.single('message_media'), async (req, res) => {
    try {
        const { conversationId } = req.params;
        const { content, message_type, replied_to } = req.body;
        
        // Check if user is participant
        const [participants] = await pool.execute(
            'SELECT 1 FROM conversation_participants WHERE conversation_id = ? AND user_id = ? AND left_at IS NULL',
            [conversationId, req.user.id]
        );
        
        if (participants.length === 0) {
            return res.status(403).json({ 
                success: false, 
                error: 'Not a participant',
                code: 'NOT_PARTICIPANT'
            });
        }
        
        // Validate content
        if (!content && !req.file) {
            return res.status(400).json({ 
                success: false, 
                error: 'Message content or media is required',
                code: 'EMPTY_MESSAGE'
            });
        }
        
        // Handle file upload
        let mediaUrl = null;
        let finalMessageType = message_type || 'text';
        
        if (req.file) {
            mediaUrl = `/uploads/messages/${req.file.filename}`;
            if (isImage(req.file.mimetype)) {
                finalMessageType = 'image';
            } else if (isVideo(req.file.mimetype)) {
                finalMessageType = 'video';
            } else if (isAudio(req.file.mimetype)) {
                finalMessageType = 'audio';
            } else {
                finalMessageType = 'file';
            }
        }
        
        // Create message
        const [result] = await pool.execute(
            `INSERT INTO messages (conversation_id, sender_id, content, message_type, media_url, replied_to)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [conversationId, req.user.id, content || '', finalMessageType, mediaUrl, replied_to || null]
        );
        
        // Get message with sender info
        const [messages] = await pool.execute(
            `SELECT m.*, u.username, u.full_name, u.profile_pic 
             FROM messages m
             JOIN users u ON m.sender_id = u.id
             WHERE m.id = ?`,
            [result.insertId]
        );
        
        const message = messages[0];
        
        // Emit socket event
        io.to(`conversation_${conversationId}`).emit('new_message', message);
        
        // Create notifications for other participants
        const [otherParticipants] = await pool.execute(
            'SELECT user_id FROM conversation_participants WHERE conversation_id = ? AND user_id != ? AND left_at IS NULL',
            [conversationId, req.user.id]
        );
        
        for (const participant of otherParticipants) {
            const participantSocketId = onlineUsers.get(participant.user_id);
            if (!participantSocketId) {
                await pool.execute(
                    `INSERT INTO notifications (user_id, type, sender_id, conversation_id, content)
                     VALUES (?, 'message', ?, ?, ?)`,
                    [participant.user_id, req.user.id, conversationId,
                     `New message from ${req.user.full_name}`]
                );
            }
        }
        
        res.status(201).json({
            success: true,
            message: 'Message sent successfully',
            data: message
        });
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to send message',
            code: 'SEND_MESSAGE_FAILED'
        });
    }
});

app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
    try {
        const { messageId } = req.params;
        
        // Check if user owns the message
        const [messages] = await pool.execute(
            'SELECT sender_id, conversation_id FROM messages WHERE id = ?',
            [messageId]
        );
        
        if (messages.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Message not found',
                code: 'MESSAGE_NOT_FOUND'
            });
        }
        
        const message = messages[0];
        
        if (message.sender_id !== req.user.id) {
            return res.status(403).json({ 
                success: false, 
                error: 'Not authorized to delete this message',
                code: 'UNAUTHORIZED'
            });
        }
        
        // Soft delete
        await pool.execute(
            'UPDATE messages SET is_deleted = TRUE WHERE id = ?',
            [messageId]
        );
        
        // Emit socket event
        io.to(`conversation_${message.conversation_id}`).emit('message_deleted', { messageId });
        
        res.json({ 
            success: true, 
            message: 'Message deleted successfully' 
        });
    } catch (error) {
        console.error('Delete message error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete message',
            code: 'DELETE_MESSAGE_FAILED'
        });
    }
});

// 6. GROUPS ROUTES
app.post('/api/groups', authenticateToken, upload.fields([
    { name: 'group_photo', maxCount: 1 },
    { name: 'cover_photo', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, description, privacy, rules } = req.body;
        
        if (!name) {
            return res.status(400).json({ 
                success: false, 
                error: 'Group name is required',
                code: 'MISSING_GROUP_NAME'
            });
        }
        
        // Handle file uploads
        let groupPhoto = null;
        let coverPhoto = null;
        
        if (req.files?.group_photo) {
            groupPhoto = `/uploads/groups/${req.files.group_photo[0].filename}`;
        }
        if (req.files?.cover_photo) {
            coverPhoto = `/uploads/covers/${req.files.cover_photo[0].filename}`;
        }
        
        // Create group
        const [result] = await pool.execute(
            `INSERT INTO groups (name, description, group_photo, cover_photo, 
                                creator_id, privacy, rules)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [name, description || '', groupPhoto, coverPhoto, req.user.id, privacy || 'public', rules || '']
        );
        
        const groupId = result.insertId;
        
        // Add creator as admin
        await pool.execute(
            'INSERT INTO group_members (group_id, user_id, role, status) VALUES (?, ?, "admin", "approved")',
            [groupId, req.user.id]
        );
        
        // Update member count
        await pool.execute(
            'UPDATE groups SET member_count = 1 WHERE id = ?',
            [groupId]
        );
        
        res.status(201).json({
            success: true,
            message: 'Group created successfully',
            data: { groupId }
        });
    } catch (error) {
        console.error('Create group error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create group',
            code: 'CREATE_GROUP_FAILED'
        });
    }
});

app.get('/api/groups', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const offset = parseInt(req.query.offset) || 0;
        const search = req.query.search || '';
        
        let query = `
            SELECT g.*, 
                   gm.role as user_role,
                   gm.status as user_status,
                   (SELECT COUNT(*) FROM group_members WHERE group_id = g.id AND status = 'approved') as member_count
            FROM groups g
            LEFT JOIN group_members gm ON g.id = gm.group_id AND gm.user_id = ?
            WHERE (g.privacy = 'public' OR gm.user_id IS NOT NULL)
        `;
        
        const params = [req.user.id];
        
        if (search) {
            query += ' AND (g.name LIKE ? OR g.description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }
        
        query += ' ORDER BY g.created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);
        
        const [groups] = await pool.execute(query, params);
        
        res.json({
            success: true,
            data: groups
        });
    } catch (error) {
        console.error('Get groups error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch groups',
            code: 'FETCH_GROUPS_FAILED'
        });
    }
});

app.post('/api/groups/:groupId/join', authenticateToken, async (req, res) => {
    try {
        const { groupId } = req.params;
        
        // Get group privacy
        const [groups] = await pool.execute(
            'SELECT privacy FROM groups WHERE id = ?',
            [groupId]
        );
        
        if (groups.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Group not found',
                code: 'GROUP_NOT_FOUND'
            });
        }
        
        const group = groups[0];
        
        // Check if already a member
        const [existing] = await pool.execute(
            'SELECT status FROM group_members WHERE group_id = ? AND user_id = ?',
            [groupId, req.user.id]
        );
        
        if (existing.length > 0) {
            const status = existing[0].status;
            return res.status(400).json({ 
                success: false, 
                error: `Already ${status === 'pending' ? 'requested to join' : 'a member'}`,
                code: 'ALREADY_MEMBER'
            });
        }
        
        let status = 'approved';
        if (group.privacy === 'private') {
            status = 'pending';
        }
        
        // Add member
        await pool.execute(
            'INSERT INTO group_members (group_id, user_id, status) VALUES (?, ?, ?)',
            [groupId, req.user.id, status]
        );
        
        // Update member count if approved
        if (status === 'approved') {
            await pool.execute(
                'UPDATE groups SET member_count = member_count + 1 WHERE id = ?',
                [groupId]
            );
        }
        
        res.json({
            success: true,
            message: `Request to join group ${status}`,
            data: { status }
        });
    } catch (error) {
        console.error('Join group error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to join group',
            code: 'JOIN_GROUP_FAILED'
        });
    }
});

app.get('/api/groups/:groupId', authenticateToken, async (req, res) => {
    try {
        const { groupId } = req.params;
        
        const [groups] = await pool.execute(
            `SELECT g.*, 
                   gm.role as user_role,
                   gm.status as user_status,
                   u.username as creator_username,
                   u.full_name as creator_name
            FROM groups g
            LEFT JOIN group_members gm ON g.id = gm.group_id AND gm.user_id = ?
            JOIN users u ON g.creator_id = u.id
            WHERE g.id = ?`,
            [req.user.id, groupId]
        );
        
        if (groups.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Group not found',
                code: 'GROUP_NOT_FOUND'
            });
        }
        
        const group = groups[0];
        
        // Check access for private groups
        if (group.privacy === 'private' && !group.user_role && group.creator_id !== req.user.id) {
            return res.status(403).json({ 
                success: false, 
                error: 'Private group access denied',
                code: 'PRIVATE_GROUP'
            });
        }
        
        // Get members
        const [members] = await pool.execute(
            `SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online, gm.role, gm.status, gm.joined_at
             FROM group_members gm
             JOIN users u ON gm.user_id = u.id
             WHERE gm.group_id = ? AND gm.status = 'approved'
             ORDER BY 
                 CASE gm.role 
                     WHEN 'admin' THEN 1
                     WHEN 'moderator' THEN 2
                     ELSE 3
                 END,
                 gm.joined_at`,
            [groupId]
        );
        
        // Get pending requests if user is admin/moderator
        let pendingRequests = [];
        if (group.user_role === 'admin' || group.user_role === 'moderator') {
            const [requests] = await pool.execute(
                `SELECT u.id, u.username, u.full_name, u.profile_pic, gm.joined_at
                 FROM group_members gm
                 JOIN users u ON gm.user_id = u.id
                 WHERE gm.group_id = ? AND gm.status = 'pending'`,
                [groupId]
            );
            pendingRequests = requests;
        }
        
        res.json({
            success: true,
            data: {
                ...group,
                members,
                pending_requests: pendingRequests
            }
        });
    } catch (error) {
        console.error('Get group error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch group',
            code: 'FETCH_GROUP_FAILED'
        });
    }
});

app.post('/api/groups/:groupId/posts', authenticateToken, async (req, res) => {
    try {
        const { groupId } = req.params;
        const { content, media_url } = req.body;
        
        if (!content && !media_url) {
            return res.status(400).json({ 
                success: false, 
                error: 'Content or media is required',
                code: 'EMPTY_POST'
            });
        }
        
        // Check if user is approved member
        const [membership] = await pool.execute(
            'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ? AND status = "approved"',
            [groupId, req.user.id]
        );
        
        if (membership.length === 0) {
            return res.status(403).json({ 
                success: false, 
                error: 'Not a member of this group',
                code: 'NOT_MEMBER'
            });
        }
        
        // Create group post
        const [result] = await pool.execute(
            'INSERT INTO group_posts (group_id, user_id, content, media_url) VALUES (?, ?, ?, ?)',
            [groupId, req.user.id, content || '', media_url || null]
        );
        
        // Update post count
        await pool.execute(
            'UPDATE groups SET post_count = post_count + 1 WHERE id = ?',
            [groupId]
        );
        
        res.status(201).json({
            success: true,
            message: 'Post created in group',
            data: { postId: result.insertId }
        });
    } catch (error) {
        console.error('Create group post error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create group post',
            code: 'CREATE_GROUP_POST_FAILED'
        });
    }
});

// 7. NOTIFICATION ROUTES
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const offset = parseInt(req.query.offset) || 0;
        const unreadOnly = req.query.unread === 'true';
        
        let query = `
            SELECT n.*, u.username, u.full_name, u.profile_pic as sender_profile_pic
            FROM notifications n
            LEFT JOIN users u ON n.sender_id = u.id
            WHERE n.user_id = ?
        `;
        
        const params = [req.user.id];
        
        if (unreadOnly) {
            query += ' AND n.is_read = FALSE';
        }
        
        query += ' ORDER BY n.created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);
        
        const [notifications] = await pool.execute(query, params);
        
        // Get unread count
        const [unreadCountResult] = await pool.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = FALSE',
            [req.user.id]
        );
        
        res.json({
            success: true,
            data: notifications,
            unread_count: unreadCountResult[0].count,
            pagination: {
                limit,
                offset,
                hasMore: notifications.length === limit
            }
        });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch notifications',
            code: 'FETCH_NOTIFICATIONS_FAILED'
        });
    }
});

app.post('/api/notifications/:notificationId/read', authenticateToken, async (req, res) => {
    try {
        const { notificationId } = req.params;
        
        const [result] = await pool.execute(
            'UPDATE notifications SET is_read = TRUE WHERE id = ? AND user_id = ?',
            [notificationId, req.user.id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Notification not found',
                code: 'NOTIFICATION_NOT_FOUND'
            });
        }
        
        res.json({
            success: true,
            message: 'Notification marked as read'
        });
    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to mark notification as read',
            code: 'MARK_READ_FAILED'
        });
    }
});

app.post('/api/notifications/read-all', authenticateToken, async (req, res) => {
    try {
        await pool.execute(
            'UPDATE notifications SET is_read = TRUE WHERE user_id = ?',
            [req.user.id]
        );
        
        res.json({
            success: true,
            message: 'All notifications marked as read'
        });
    } catch (error) {
        console.error('Mark all notifications read error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to mark notifications as read',
            code: 'MARK_ALL_READ_FAILED'
        });
    }
});

// 8. BIRTHDAY ROUTES
app.get('/api/birthdays/upcoming', authenticateToken, async (req, res) => {
    try {
        const [birthdays] = await pool.execute(
            `SELECT u.id, u.username, u.full_name, u.profile_pic, 
                    DATE_FORMAT(u.birthdate, '%M %d') as birthdate_formatted,
                    DAY(u.birthdate) as birth_day,
                    MONTH(u.birthdate) as birth_month,
                    CASE 
                        WHEN DATE_FORMAT(u.birthdate, '%m-%d') = DATE_FORMAT(CURDATE(), '%m-%d') THEN 'today'
                        WHEN DATE_FORMAT(u.birthdate, '%m-%d') = DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 1 DAY), '%m-%d') THEN 'tomorrow'
                        WHEN DATE_FORMAT(u.birthdate, '%m-%d') BETWEEN DATE_FORMAT(CURDATE(), '%m-%d') 
                            AND DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 7 DAY), '%m-%d') THEN 'this_week'
                        ELSE 'upcoming'
                    END as timeframe
             FROM users u
             JOIN friendships f ON (f.user1_id = u.id AND f.user2_id = ?) OR (f.user1_id = ? AND f.user2_id = u.id)
             WHERE u.birthdate IS NOT NULL
                AND (MONTH(u.birthdate) > MONTH(CURDATE()) 
                     OR (MONTH(u.birthdate) = MONTH(CURDATE()) AND DAY(u.birthdate) >= DAY(CURDATE())))
             ORDER BY MONTH(u.birthdate), DAY(u.birthdate)
             LIMIT 20`,
            [req.user.id, req.user.id]
        );
        
        res.json({
            success: true,
            data: birthdays
        });
    } catch (error) {
        console.error('Get birthdays error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch birthdays',
            code: 'FETCH_BIRTHDAYS_FAILED'
        });
    }
});

app.post('/api/birthdays/:userId/wish', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const { message, gift_type = 'cake' } = req.body;
        
        if (!message) {
            return res.status(400).json({ 
                success: false, 
                error: 'Message is required',
                code: 'MISSING_MESSAGE'
            });
        }
        
        const validGifts = ['cake', 'balloon', 'gift', 'heart'];
        if (!validGifts.includes(gift_type)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid gift type',
                code: 'INVALID_GIFT'
            });
        }
        
        // Check if user is friend
        const [friendship] = await pool.execute(
            `SELECT 1 FROM friendships 
             WHERE (user1_id = ? AND user2_id = ?) 
                OR (user1_id = ? AND user2_id = ?)`,
            [req.user.id, userId, userId, req.user.id]
        );
        
        if (friendship.length === 0) {
            return res.status(403).json({ 
                success: false, 
                error: 'Must be friends to send birthday wishes',
                code: 'NOT_FRIENDS'
            });
        }
        
        // Check if today is their birthday
        const [birthdayUser] = await pool.execute(
            `SELECT id, full_name FROM users 
             WHERE id = ? AND DATE_FORMAT(birthdate, '%m-%d') = DATE_FORMAT(CURDATE(), '%m-%d')`,
            [userId]
        );
        
        if (birthdayUser.length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Not their birthday today',
                code: 'NOT_BIRTHDAY'
            });
        }
        
        // Create birthday wish
        await pool.execute(
            'INSERT INTO birthday_wishes (birthday_user_id, sender_id, message, gift_type) VALUES (?, ?, ?, ?)',
            [userId, req.user.id, message, gift_type]
        );
        
        // Create notification
        await pool.execute(
            `INSERT INTO notifications (user_id, type, sender_id, content) 
             VALUES (?, 'birthday', ?, ?)`,
            [userId, req.user.id, `${req.user.full_name} sent you a birthday wish`]
        );
        
        // Emit socket event
        const birthdayUserSocketId = onlineUsers.get(userId);
        if (birthdayUserSocketId) {
            io.to(birthdayUserSocketId).emit('birthday_wish', {
                userId: req.user.id,
                userName: req.user.full_name,
                giftType: gift_type,
                message: message
            });
        }
        
        res.status(201).json({
            success: true,
            message: 'Birthday wish sent'
        });
    } catch (error) {
        console.error('Send birthday wish error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to send birthday wish',
            code: 'SEND_WISH_FAILED'
        });
    }
});

// 9. DIGITAL ID CARD ROUTES
app.get('/api/users/me/qrcode', authenticateToken, async (req, res) => {
    try {
        const shareableLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/profile/${req.user.username}`;
        
        // Generate QR code
        const qrCodeData = JSON.stringify({
            userId: req.user.id,
            username: req.user.username,
            fullName: req.user.full_name,
            profileUrl: shareableLink,
            timestamp: Date.now()
        });
        
        // Generate QR code image URL
        const qrCodeImage = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(shareableLink)}`;
        
        // Save or update in database
        const [existing] = await pool.execute(
            'SELECT id FROM user_qr_codes WHERE user_id = ?',
            [req.user.id]
        );
        
        if (existing.length > 0) {
            await pool.execute(
                'UPDATE user_qr_codes SET qr_code_data = ?, qr_code_image = ?, shareable_link = ?, updated_at = NOW() WHERE user_id = ?',
                [qrCodeData, qrCodeImage, shareableLink, req.user.id]
            );
        } else {
            await pool.execute(
                `INSERT INTO user_qr_codes (user_id, qr_code_data, qr_code_image, shareable_link) 
                 VALUES (?, ?, ?, ?)`,
                [req.user.id, qrCodeData, qrCodeImage, shareableLink]
            );
        }
        
        res.json({
            success: true,
            data: {
                qr_code_data: qrCodeData,
                qr_code_image: qrCodeImage,
                shareable_link: shareableLink
            }
        });
    } catch (error) {
        console.error('Generate QR code error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to generate QR code',
            code: 'QR_CODE_FAILED'
        });
    }
});

// 10. FAKE ACCOUNT DETECTION & REPORTING
app.post('/api/reports/user', authenticateToken, async (req, res) => {
    try {
        const { reported_user_id, report_type, description, evidence } = req.body;
        
        if (!reported_user_id || !report_type) {
            return res.status(400).json({ 
                success: false, 
                error: 'Reported user ID and type are required',
                code: 'MISSING_REPORT_DATA'
            });
        }
        
        if (reported_user_id === req.user.id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Cannot report yourself',
                code: 'SELF_REPORT'
            });
        }
        
        // Check if user exists
        const [users] = await pool.execute(
            'SELECT id, username FROM users WHERE id = ?',
            [reported_user_id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        // Check if already reported recently
        const [existing] = await pool.execute(
            'SELECT id FROM user_reports WHERE reporter_id = ? AND reported_user_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)',
            [req.user.id, reported_user_id]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Already reported this user recently',
                code: 'ALREADY_REPORTED'
            });
        }
        
        // Create report
        await pool.execute(
            `INSERT INTO user_reports (reporter_id, reported_user_id, report_type, description, evidence) 
             VALUES (?, ?, ?, ?, ?)`,
            [req.user.id, reported_user_id, report_type, description || '', 
             evidence ? JSON.stringify(evidence) : null]
        );
        
        // Log suspicious activity
        await pool.execute(
            `INSERT INTO suspicious_activities (user_id, activity_type, details) 
             VALUES (?, 'user_reported', ?)`,
            [reported_user_id, JSON.stringify({ 
                reporter_id: req.user.id, 
                report_type: report_type,
                timestamp: new Date().toISOString()
            })]
        );
        
        res.status(201).json({
            success: true,
            message: 'User reported successfully'
        });
    } catch (error) {
        console.error('Report user error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to report user',
            code: 'REPORT_FAILED'
        });
    }
});

// 11. TRENDING POSTS
app.get('/api/posts/trending', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        
        const [trendingPosts] = await pool.execute(
            `SELECT p.*, u.username, u.full_name, u.profile_pic,
                    COUNT(DISTINCT pr.id) + COUNT(DISTINCT c.id)*2 + COUNT(DISTINCT s.id)*3 as engagement_score,
                    COUNT(DISTINCT pr.id) as reaction_count,
                    COUNT(DISTINCT c.id) as comment_count,
                    COUNT(DISTINCT s.id) as share_count
             FROM posts p
             JOIN users u ON p.user_id = u.id
             LEFT JOIN post_reactions pr ON p.id = pr.post_id AND pr.created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             LEFT JOIN comments c ON p.id = c.post_id AND c.created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             LEFT JOIN shares s ON p.id = s.post_id AND s.created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             WHERE p.is_deleted = FALSE AND p.privacy = 'public'
                AND p.created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
             GROUP BY p.id
             ORDER BY engagement_score DESC, p.created_at DESC
             LIMIT ?`,
            [limit]
        );
        
        res.json({
            success: true,
            data: trendingPosts
        });
    } catch (error) {
        console.error('Get trending posts error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch trending posts',
            code: 'FETCH_TRENDING_FAILED'
        });
    }
});

// 12. STORIES
app.post('/api/stories', authenticateToken, upload.single('story_media'), async (req, res) => {
    try {
        const { text_content, bg_color = '#000000', font_style = 'Arial' } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                error: 'Media file is required',
                code: 'MISSING_MEDIA'
            });
        }
        
        const mediaType = isImage(req.file.mimetype) ? 'image' : 'video';
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
        
        const [result] = await pool.execute(
            `INSERT INTO stories (user_id, media_url, media_type, text_content, bg_color, font_style, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [req.user.id, `/uploads/stories/${req.file.filename}`, mediaType, text_content || '', bg_color, font_style, expiresAt]
        );
        
        res.status(201).json({
            success: true,
            message: 'Story created successfully',
            data: {
                storyId: result.insertId,
                expiresAt: expiresAt.toISOString()
            }
        });
    } catch (error) {
        console.error('Create story error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create story',
            code: 'CREATE_STORY_FAILED'
        });
    }
});

app.get('/api/stories/feed', authenticateToken, async (req, res) => {
    try {
        const [stories] = await pool.execute(
            `SELECT s.*, u.username, u.full_name, u.profile_pic,
                    (SELECT COUNT(*) FROM story_views WHERE story_id = s.id) as view_count,
                    EXISTS(SELECT 1 FROM story_views WHERE story_id = s.id AND viewer_id = ?) as has_viewed
             FROM stories s
             JOIN users u ON s.user_id = u.id
             WHERE s.expires_at > NOW()
                AND (u.id = ? 
                     OR EXISTS(
                         SELECT 1 FROM friendships 
                         WHERE (user1_id = ? AND user2_id = u.id) 
                            OR (user1_id = u.id AND user2_id = ?)
                     ))
             ORDER BY s.created_at DESC`,
            [req.user.id, req.user.id, req.user.id, req.user.id]
        );
        
        // Group stories by user
        const groupedStories = {};
        stories.forEach(story => {
            if (!groupedStories[story.user_id]) {
                groupedStories[story.user_id] = {
                    user: {
                        id: story.user_id,
                        username: story.username,
                        full_name: story.full_name,
                        profile_pic: story.profile_pic
                    },
                    stories: []
                };
            }
            groupedStories[story.user_id].stories.push({
                id: story.id,
                media_url: story.media_url,
                media_type: story.media_type,
                text_content: story.text_content,
                bg_color: story.bg_color,
                font_style: story.font_style,
                created_at: story.created_at,
                expires_at: story.expires_at,
                view_count: story.view_count,
                has_viewed: story.has_viewed
            });
        });
        
        res.json({
            success: true,
            data: Object.values(groupedStories)
        });
    } catch (error) {
        console.error('Get stories error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch stories',
            code: 'FETCH_STORIES_FAILED'
        });
    }
});

app.post('/api/stories/:storyId/view', authenticateToken, async (req, res) => {
    try {
        const { storyId } = req.params;
        
        // Check if story exists and not expired
        const [stories] = await pool.execute(
            'SELECT user_id FROM stories WHERE id = ? AND expires_at > NOW()',
            [storyId]
        );
        
        if (stories.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Story not found or expired',
                code: 'STORY_NOT_FOUND'
            });
        }
        
        const story = stories[0];
        
        // Check if user can view (friends or own story)
        if (story.user_id !== req.user.id) {
            const [friendship] = await pool.execute(
                `SELECT 1 FROM friendships 
                 WHERE (user1_id = ? AND user2_id = ?) 
                    OR (user1_id = ? AND user2_id = ?)`,
                [req.user.id, story.user_id, story.user_id, req.user.id]
            );
            
            if (friendship.length === 0) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'Cannot view this story',
                    code: 'STORY_VIEW_NOT_ALLOWED'
                });
            }
        }
        
        // Record view
        await pool.execute(
            'INSERT INTO story_views (story_id, viewer_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE viewed_at = NOW()',
            [storyId, req.user.id]
        );
        
        res.json({
            success: true,
            message: 'Story viewed'
        });
    } catch (error) {
        console.error('View story error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to record story view',
            code: 'VIEW_STORY_FAILED'
        });
    }
});

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Global error:', err.stack);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ 
                success: false, 
                error: 'File too large. Maximum size is 50MB',
                code: 'FILE_TOO_LARGE'
            });
        }
        return res.status(400).json({ 
            success: false, 
            error: 'File upload error',
            code: 'UPLOAD_ERROR',
            details: err.message
        });
    }
    
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error',
        code: 'INTERNAL_ERROR',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found',
        code: 'ENDPOINT_NOT_FOUND'
    });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Database: ${process.env.DB_HOST}/${process.env.DB_NAME}`);
    console.log(`👤 Database User: ${process.env.DB_USER}`);
    console.log(`🌐 Frontend URL: ${process.env.FRONTEND_URL}`);
    console.log(`📧 Email: ${process.env.EMAIL_USER}`);
    console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Not set (using default)'}`);
});
