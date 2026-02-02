// backend/server.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const QRCode = require('qrcode');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const socketIo = require('socket.io');
const http = require('http');

// Initialize app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        methods: ["GET", "POST"]
    }
});

// Database connection
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'friendsconnect',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|mp4|avi|mov|wmv/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Error: File type not supported!'));
        }
    }
});

// Email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await db.execute(
            'SELECT id, username, email, is_verified FROM users WHERE id = ?',
            [decoded.userId]
        );
        
        if (users.length === 0) {
            return res.status(403).json({ error: 'User not found' });
        }
        
        req.user = users[0];
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Admin middleware
const authenticateAdmin = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [admins] = await db.execute(
            'SELECT id, username, role FROM admin_users WHERE id = ?',
            [decoded.adminId]
        );
        
        if (admins.length === 0) {
            return res.status(403).json({ error: 'Admin not found' });
        }
        
        req.admin = admins[0];
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid admin token' });
    }
};

// ==================== API ROUTES ====================

// 1. AUTHENTICATION ROUTES
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, full_name, birth_date } = req.body;
        
        // Check if user exists
        const [existingUsers] = await db.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [email, username]
        );
        
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generate verification code
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Generate public ID
        const publicId = crypto.randomBytes(10).toString('hex');
        
        // Create user
        const [result] = await db.execute(
            `INSERT INTO users 
            (username, email, password_hash, full_name, birth_date, verification_code, public_id) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [username, email, hashedPassword, full_name, birth_date, verificationCode, publicId]
        );
        
        // Create default settings
        await db.execute(
            'INSERT INTO user_settings (user_id) VALUES (?)',
            [result.insertId]
        );
        
        // Create birthday record
        await db.execute(
            'INSERT INTO birthdays (user_id, birth_date) VALUES (?, ?)',
            [result.insertId, birth_date]
        );
        
        // Generate digital ID
        const qrData = JSON.stringify({
            userId: result.insertId,
            username: username,
            publicId: publicId
        });
        
        const qrCode = await QRCode.toDataURL(qrData);
        
        await db.execute(
            'INSERT INTO digital_ids (user_id, qr_code_data, card_data) VALUES (?, ?, ?)',
            [
                result.insertId,
                qrCode,
                JSON.stringify({
                    name: full_name,
                    username: username,
                    memberSince: new Date().toISOString().split('T')[0],
                    qrCode: qrCode
                })
            ]
        );
        
        // Send verification email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify Your FriendsConnect Account',
            html: `
                <h1>Welcome to FriendsConnect!</h1>
                <p>Your verification code is: <strong>${verificationCode}</strong></p>
                <p>Enter this code in the app to verify your account.</p>
            `
        });
        
        res.status(201).json({ 
            message: 'User registered successfully. Please check your email for verification.',
            userId: result.insertId
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        
        const [users] = await db.execute(
            'SELECT id, verification_code FROM users WHERE email = ?',
            [email]
        );
        
        if (users.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }
        
        const user = users[0];
        
        if (user.verification_code !== code) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }
        
        // Update user as verified
        await db.execute(
            'UPDATE users SET is_verified = TRUE, verification_code = NULL WHERE id = ?',
            [user.id]
        );
        
        // Generate JWT token
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ 
            message: 'Account verified successfully',
            token,
            userId: user.id
        });
        
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Verification failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, twoFactorCode } = req.body;
        const ip = req.ip;
        const userAgent = req.headers['user-agent'];
        
        // Check user
        const [users] = await db.execute(
            'SELECT id, email, password_hash, two_factor_enabled FROM users WHERE email = ?',
            [email]
        );
        
        if (users.length === 0) {
            await db.execute(
                'INSERT INTO login_logs (email, ip_address, user_agent, success) VALUES (?, ?, ?, ?)',
                [email, ip, userAgent, false]
            );
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            await db.execute(
                'INSERT INTO login_logs (user_id, ip_address, user_agent, success) VALUES (?, ?, ?, ?)',
                [user.id, ip, userAgent, false]
            );
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Handle 2FA if enabled
        if (user.two_factor_enabled && !twoFactorCode) {
            return res.status(200).json({ 
                requires2FA: true,
                message: 'Two-factor authentication required'
            });
        }
        
        // Update last login
        await db.execute(
            'UPDATE users SET last_seen = NOW() WHERE id = ?',
            [user.id]
        );
        
        // Log successful login
        await db.execute(
            'INSERT INTO login_logs (user_id, ip_address, user_agent, success) VALUES (?, ?, ?, ?)',
            [user.id, ip, userAgent, true]
        );
        
        // Generate JWT token
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ 
            message: 'Login successful',
            token,
            userId: user.id,
            requires2FA: false
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// 2. USER PROFILE ROUTES
app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.id;
        
        const [users] = await db.execute(`
            SELECT 
                u.id, u.username, u.full_name, u.avatar_url, u.cover_url, 
                u.bio, u.location, u.interests, u.birth_date, u.gender,
                u.is_verified, u.is_premium, u.online_status, u.last_seen,
                u.post_count, u.friend_count, u.profile_score, u.public_id,
                d.qr_code_data, d.card_data,
                s.theme, s.glassmorphism
            FROM users u
            LEFT JOIN digital_ids d ON u.id = d.user_id
            LEFT JOIN user_settings s ON u.id = s.user_id
            WHERE u.id = ?
        `, [userId]);
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = users[0];
        
        // Check friendship status
        const [friendship] = await db.execute(
            `SELECT status FROM friendships 
            WHERE (user_id = ? AND friend_id = ?) 
               OR (user_id = ? AND friend_id = ?)`,
            [req.user.id, userId, userId, req.user.id]
        );
        
        // Get mutual friends count
        const [mutualFriends] = await db.execute(`
            SELECT COUNT(*) as count FROM friendships f1
            JOIN friendships f2 ON f1.friend_id = f2.friend_id
            WHERE f1.user_id = ? AND f2.user_id = ? 
              AND f1.status = 'accepted' AND f2.status = 'accepted'
        `, [req.user.id, userId]);
        
        user.friendshipStatus = friendship.length > 0 ? friendship[0].status : 'none';
        user.mutualFriends = mutualFriends[0].count;
        
        res.json({ user });
        
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Failed to get user' });
    }
});

app.put('/api/users/profile', authenticateToken, upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'cover', maxCount: 1 }
]), async (req, res) => {
    try {
        const { bio, location, interests, phone } = req.body;
        const userId = req.user.id;
        
        let updateFields = [];
        let updateValues = [];
        
        if (bio !== undefined) {
            updateFields.push('bio = ?');
            updateValues.push(bio);
        }
        
        if (location !== undefined) {
            updateFields.push('location = ?');
            updateValues.push(location);
        }
        
        if (interests !== undefined) {
            updateFields.push('interests = ?');
            updateValues.push(JSON.stringify(interests.split(',').map(i => i.trim())));
        }
        
        if (phone !== undefined) {
            updateFields.push('phone = ?');
            updateValues.push(phone);
        }
        
        // Handle avatar upload
        if (req.files && req.files.avatar) {
            const avatarUrl = `/uploads/${req.files.avatar[0].filename}`;
            updateFields.push('avatar_url = ?');
            updateValues.push(avatarUrl);
        }
        
        // Handle cover upload
        if (req.files && req.files.cover) {
            const coverUrl = `/uploads/${req.files.cover[0].filename}`;
            updateFields.push('cover_url = ?');
            updateValues.push(coverUrl);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }
        
        updateValues.push(userId);
        
        await db.execute(
            `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
            updateValues
        );
        
        // Update profile score
        await db.execute(`
            UPDATE users 
            SET profile_score = 
                (CASE WHEN avatar_url IS NOT NULL THEN 20 ELSE 0 END) +
                (CASE WHEN bio IS NOT NULL THEN 15 ELSE 0 END) +
                (CASE WHEN location IS NOT NULL THEN 15 ELSE 0 END) +
                (CASE WHEN post_count > 5 THEN 25 ELSE post_count * 5 END) +
                (CASE WHEN friend_count BETWEEN 5 AND 100 THEN 25 ELSE 0 END)
            WHERE id = ?
        `, [userId]);
        
        res.json({ message: 'Profile updated successfully' });
        
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// 3. FRIEND SYSTEM ROUTES
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    try {
        const { friendId, friendUsername, qrCodeData } = req.body;
        const userId = req.user.id;
        
        let targetUserId;
        
        // Find user by different methods
        if (friendId) {
            targetUserId = friendId;
        } else if (friendUsername) {
            const [users] = await db.execute(
                'SELECT id FROM users WHERE username = ?',
                [friendUsername]
            );
            if (users.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            targetUserId = users[0].id;
        } else if (qrCodeData) {
            // Decode QR code
            const qrData = JSON.parse(qrCodeData);
            targetUserId = qrData.userId;
        } else {
            return res.status(400).json({ error: 'No identification method provided' });
        }
        
        // Check if already friends
        const [existing] = await db.execute(`
            SELECT status FROM friendships 
            WHERE (user_id = ? AND friend_id = ?) 
               OR (user_id = ? AND friend_id = ?)
        `, [userId, targetUserId, targetUserId, userId]);
        
        if (existing.length > 0) {
            const status = existing[0].status;
            if (status === 'accepted') {
                return res.status(400).json({ error: 'Already friends' });
            } else if (status === 'pending') {
                return res.status(400).json({ error: 'Friend request already sent' });
            } else if (status === 'blocked') {
                return res.status(400).json({ error: 'Cannot send friend request' });
            }
        }
        
        // Check if blocked
        const [blocked] = await db.execute(
            'SELECT id FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?',
            [targetUserId, userId]
        );
        
        if (blocked.length > 0) {
            return res.status(400).json({ error: 'Cannot send friend request' });
        }
        
        // Create friend request
        await db.execute(
            'INSERT INTO friendships (user_id, friend_id, status) VALUES (?, ?, ?)',
            [userId, targetUserId, 'pending']
        );
        
        // Create notification
        await db.execute(
            `INSERT INTO notifications 
            (user_id, type, title, message, related_id, related_type) 
            VALUES (?, 'friend_request', 'New Friend Request', 
            'You have a new friend request from ?', ?, 'user')`,
            [targetUserId, req.user.full_name || req.user.username, userId]
        );
        
        res.json({ message: 'Friend request sent successfully' });
        
    } catch (error) {
        console.error('Friend request error:', error);
        res.status(500).json({ error: 'Failed to send friend request' });
    }
});

app.post('/api/friends/respond', authenticateToken, async (req, res) => {
    try {
        const { requestId, action } = req.body; // action: 'accept' or 'reject'
        const userId = req.user.id;
        
        // Get friend request
        const [requests] = await db.execute(`
            SELECT f.*, u.username, u.full_name 
            FROM friendships f
            JOIN users u ON f.user_id = u.id
            WHERE f.id = ? AND f.friend_id = ? AND f.status = 'pending'
        `, [requestId, userId]);
        
        if (requests.length === 0) {
            return res.status(404).json({ error: 'Friend request not found' });
        }
        
        const request = requests[0];
        
        if (action === 'accept') {
            // Update friendship status
            await db.execute(
                'UPDATE friendships SET status = ? WHERE id = ?',
                ['accepted', requestId]
            );
            
            // Create reciprocal friendship
            await db.execute(
                'INSERT INTO friendships (user_id, friend_id, status) VALUES (?, ?, ?)',
                [userId, request.user_id, 'accepted']
            );
            
            // Update friend counts
            await db.execute(
                'UPDATE users SET friend_count = friend_count + 1 WHERE id IN (?, ?)',
                [userId, request.user_id]
            );
            
            // Create notification
            await db.execute(
                `INSERT INTO notifications 
                (user_id, type, title, message, related_id, related_type) 
                VALUES (?, 'friend_accepted', 'Friend Request Accepted', 
                '? accepted your friend request', ?, 'user')`,
                [request.user_id, req.user.full_name || req.user.username, userId]
            );
            
            res.json({ message: 'Friend request accepted' });
            
        } else if (action === 'reject') {
            await db.execute(
                'UPDATE friendships SET status = ? WHERE id = ?',
                ['rejected', requestId]
            );
            
            res.json({ message: 'Friend request rejected' });
        } else {
            return res.status(400).json({ error: 'Invalid action' });
        }
        
    } catch (error) {
        console.error('Friend response error:', error);
        res.status(500).json({ error: 'Failed to process friend request' });
    }
});

app.get('/api/friends/suggestions', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // AI-style friend suggestions based on:
        // 1. Mutual friends
        // 2. Same location
        // 3. Same interests
        // 4. Profile completeness
        
        const [suggestions] = await db.execute(`
            SELECT 
                u.id, u.username, u.full_name, u.avatar_url, u.location,
                u.interests, u.profile_score,
                COUNT(DISTINCT mf.id) as mutual_friends_count,
                
                -- Calculate suggestion score
                (COUNT(DISTINCT mf.id) * 10) + 
                (CASE WHEN u.location = (SELECT location FROM users WHERE id = ?) THEN 20 ELSE 0 END) +
                (CASE WHEN JSON_OVERLAPS(u.interests, (SELECT interests FROM users WHERE id = ?)) THEN 15 ELSE 0 END) +
                (u.profile_score * 0.5) as suggestion_score
                
            FROM users u
            
            -- Mutual friends
            LEFT JOIN friendships f1 ON u.id = f1.friend_id AND f1.status = 'accepted'
            LEFT JOIN friendships f2 ON f1.user_id = f2.user_id AND f2.status = 'accepted'
            LEFT JOIN users mf ON f2.friend_id = mf.id AND mf.id != ?
            
            -- Exclude existing relationships
            LEFT JOIN friendships ef ON (ef.user_id = ? AND ef.friend_id = u.id) 
                OR (ef.user_id = u.id AND ef.friend_id = ?)
            
            WHERE u.id != ?
              AND u.is_verified = TRUE
              AND u.active_status = 'active'
              AND ef.id IS NULL -- No existing relationship
              AND u.profile_score > 30 -- Good profile score
            
            GROUP BY u.id
            HAVING suggestion_score > 0
            ORDER BY suggestion_score DESC
            LIMIT 20
        `, [userId, userId, userId, userId, userId, userId]);
        
        res.json({ suggestions });
        
    } catch (error) {
        console.error('Friend suggestions error:', error);
        res.status(500).json({ error: 'Failed to get suggestions' });
    }
});

// 4. POSTS SYSTEM ROUTES
app.post('/api/posts', authenticateToken, upload.array('media', 10), async (req, res) => {
    try {
        const { content, privacy, taggedUsers, location } = req.body;
        const userId = req.user.id;
        
        // Process media files
        const mediaUrls = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
        
        // Create post
        const [result] = await db.execute(`
            INSERT INTO posts 
            (user_id, content, media_urls, privacy, location, tagged_users) 
            VALUES (?, ?, ?, ?, ?, ?)
        `, [
            userId,
            content,
            JSON.stringify(mediaUrls),
            privacy || 'friends',
            location,
            taggedUsers ? JSON.stringify(taggedUsers.split(',').map(id => parseInt(id))) : '[]'
        ]);
        
        // Update user post count
        await db.execute(
            'UPDATE users SET post_count = post_count + 1 WHERE id = ?',
            [userId]
        );
        
        // Create notifications for tagged users
        if (taggedUsers) {
            const taggedIds = taggedUsers.split(',').map(id => parseInt(id));
            
            for (const taggedId of taggedIds) {
                await db.execute(`
                    INSERT INTO notifications 
                    (user_id, type, title, message, related_id, related_type) 
                    VALUES (?, 'mention', 'You were mentioned', 
                    '? mentioned you in a post', ?, 'post')
                `, [taggedId, req.user.full_name || req.user.username, result.insertId]);
            }
        }
        
        res.status(201).json({ 
            message: 'Post created successfully',
            postId: result.insertId
        });
        
    } catch (error) {
        console.error('Create post error:', error);
        res.status(500).json({ error: 'Failed to create post' });
    }
});

app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user.id;
        
        // Check if already liked
        const [existing] = await db.execute(
            'SELECT id FROM post_likes WHERE post_id = ? AND user_id = ?',
            [postId, userId]
        );
        
        if (existing.length > 0) {
            // Unlike
            await db.execute(
                'DELETE FROM post_likes WHERE id = ?',
                [existing[0].id]
            );
            await db.execute(
                'UPDATE posts SET like_count = like_count - 1 WHERE id = ?',
                [postId]
            );
            
            res.json({ message: 'Post unliked', liked: false });
        } else {
            // Like
            await db.execute(
                'INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)',
                [postId, userId]
            );
            await db.execute(
                'UPDATE posts SET like_count = like_count + 1 WHERE id = ?',
                [postId]
            );
            
            // Create notification for post owner
            const [post] = await db.execute(
                'SELECT user_id FROM posts WHERE id = ?',
                [postId]
            );
            
            if (post.length > 0 && post[0].user_id !== userId) {
                await db.execute(`
                    INSERT INTO notifications 
                    (user_id, type, title, message, related_id, related_type) 
                    VALUES (?, 'like', 'New Like', 
                    '? liked your post', ?, 'post')
                `, [post[0].user_id, req.user.full_name || req.user.username, postId]);
            }
            
            res.json({ message: 'Post liked', liked: true });
        }
        
    } catch (error) {
        console.error('Like post error:', error);
        res.status(500).json({ error: 'Failed to like post' });
    }
});

// 5. MESSAGES SYSTEM
const onlineUsers = new Map();

io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);
    
    // User goes online
    socket.on('user-online', async (userId) => {
        onlineUsers.set(userId, socket.id);
        
        // Update database
        await db.execute(
            'UPDATE users SET online_status = ?, last_seen = NOW() WHERE id = ?',
            ['online', userId]
        );
        
        // Notify friends
        const [friends] = await db.execute(`
            SELECT friend_id FROM friendships 
            WHERE user_id = ? AND status = 'accepted'
            UNION
            SELECT user_id FROM friendships 
            WHERE friend_id = ? AND status = 'accepted'
        `, [userId, userId]);
        
        friends.forEach(friend => {
            const friendSocketId = onlineUsers.get(friend.friend_id);
            if (friendSocketId) {
                io.to(friendSocketId).emit('friend-online', userId);
            }
        });
    });
    
    // Send message
    socket.on('send-message', async (data) => {
        try {
            const { conversationId, content, type } = data;
            const userId = socket.userId;
            
            // Save message to database
            const [result] = await db.execute(`
                INSERT INTO messages 
                (conversation_id, sender_id, message_type, content) 
                VALUES (?, ?, ?, ?)
            `, [conversationId, userId, type || 'text', content]);
            
            // Get conversation members
            const [members] = await db.execute(`
                SELECT user_id FROM conversation_members 
                WHERE conversation_id = ? AND user_id != ?
            `, [conversationId, userId]);
            
            // Send to other members
            members.forEach(member => {
                const memberSocketId = onlineUsers.get(member.user_id);
                if (memberSocketId) {
                    io.to(memberSocketId).emit('new-message', {
                        conversationId,
                        message: {
                            id: result.insertId,
                            sender_id: userId,
                            content,
                            type: type || 'text',
                            created_at: new Date()
                        }
                    });
                }
            });
            
            // Typing indicator
            socket.on('typing', (data) => {
                const { conversationId, isTyping } = data;
                socket.to(conversationId).emit('user-typing', {
                    userId: socket.userId,
                    isTyping
                });
            });
            
        } catch (error) {
            console.error('Send message error:', error);
            socket.emit('error', { message: 'Failed to send message' });
        }
    });
    
    // User goes offline
    socket.on('disconnect', async () => {
        for (const [userId, socketId] of onlineUsers.entries()) {
            if (socketId === socket.id) {
                onlineUsers.delete(userId);
                
                // Update database
                await db.execute(
                    'UPDATE users SET online_status = ?, last_seen = NOW() WHERE id = ?',
                    ['offline', userId]
                );
                
                // Notify friends
                const [friends] = await db.execute(`
                    SELECT friend_id FROM friendships 
                    WHERE user_id = ? AND status = 'accepted'
                    UNION
                    SELECT user_id FROM friendships 
                    WHERE friend_id = ? AND status = 'accepted'
                `, [userId, userId]);
                
                friends.forEach(friend => {
                    const friendSocketId = onlineUsers.get(friend.friend_id);
                    if (friendSocketId) {
                        io.to(friendSocketId).emit('friend-offline', userId);
                    }
                });
                
                break;
            }
        }
    });
});

// 6. STORIES SYSTEM
app.post('/api/stories', authenticateToken, upload.single('media'), async (req, res) => {
    try {
        const { caption } = req.body;
        const userId = req.user.id;
        const mediaUrl = `/uploads/${req.file.filename}`;
        const mediaType = req.file.mimetype.startsWith('video') ? 'video' : 'photo';
        
        // Expires in 24 hours
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        const [result] = await db.execute(`
            INSERT INTO stories 
            (user_id, media_url, media_type, caption, expires_at) 
            VALUES (?, ?, ?, ?, ?)
        `, [userId, mediaUrl, mediaType, caption, expiresAt]);
        
        res.status(201).json({ 
            message: 'Story created successfully',
            storyId: result.insertId,
            expiresAt
        });
        
    } catch (error) {
        console.error('Create story error:', error);
        res.status(500).json({ error: 'Failed to create story' });
    }
});

// 7. GROUPS SYSTEM
app.post('/api/groups', authenticateToken, upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'cover', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, description, privacy, joinApproval, postApproval } = req.body;
        const userId = req.user.id;
        
        const avatarUrl = req.files.avatar ? `/uploads/${req.files.avatar[0].filename}` : null;
        const coverUrl = req.files.cover ? `/uploads/${req.files.cover[0].filename}` : null;
        
        const [result] = await db.execute(`
            INSERT INTO groups 
            (name, description, avatar_url, cover_url, creator_id, 
             privacy, join_approval, post_approval) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            name,
            description,
            avatarUrl,
            coverUrl,
            userId,
            privacy || 'public',
            joinApproval || false,
            postApproval || false
        ]);
        
        // Add creator as admin
        await db.execute(`
            INSERT INTO group_members 
            (group_id, user_id, role) 
            VALUES (?, ?, 'admin')
        `, [result.insertId, userId]);
        
        res.status(201).json({ 
            message: 'Group created successfully',
            groupId: result.insertId
        });
        
    } catch (error) {
        console.error('Create group error:', error);
        res.status(500).json({ error: 'Failed to create group' });
    }
});

// 8. MARKETPLACE
app.post('/api/marketplace', authenticateToken, upload.array('images', 10), async (req, res) => {
    try {
        const { title, description, price, currency, category, condition, location } = req.body;
        const userId = req.user.id;
        
        const mediaUrls = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
        
        const [result] = await db.execute(`
            INSERT INTO marketplace_items 
            (seller_id, title, description, price, currency, 
             category, condition, location, media_urls) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            userId,
            title,
            description,
            parseFloat(price),
            currency || 'USD',
            category,
            condition || 'good',
            location,
            JSON.stringify(mediaUrls)
        ]);
        
        res.status(201).json({ 
            message: 'Item listed successfully',
            itemId: result.insertId
        });
        
    } catch (error) {
        console.error('List item error:', error);
        res.status(500).json({ error: 'Failed to list item' });
    }
});

// 9. FAKE ACCOUNT DETECTION
app.post('/api/report/fake-account', authenticateToken, async (req, res) => {
    try {
        const { reportedUserId, reason, evidence } = req.body;
        const reporterId = req.user.id;
        
        await db.execute(`
            INSERT INTO reports 
            (reporter_id, reported_user_id, report_type, reason, evidence_urls) 
            VALUES (?, ?, 'fake_account', ?, ?)
        `, [
            reporterId,
            reportedUserId,
            reason,
            evidence ? JSON.stringify(evidence) : '[]'
        ]);
        
        // Update user trust score
        await db.execute(
            'UPDATE users SET trust_score = trust_score - 10 WHERE id = ?',
            [reportedUserId]
        );
        
        res.json({ message: 'Report submitted successfully' });
        
    } catch (error) {
        console.error('Report error:', error);
        res.status(500).json({ error: 'Failed to submit report' });
    }
});

// 10. ADMIN ROUTES
app.get('/api/admin/fake-accounts', authenticateAdmin, async (req, res) => {
    try {
        const [accounts] = await db.execute(`
            SELECT 
                u.id, u.username, u.email, u.full_name, 
                u.avatar_url, u.trust_score, u.profile_score,
                u.post_count, u.friend_count, u.account_age_days,
                u.created_at,
                COUNT(r.id) as report_count
            FROM users u
            LEFT JOIN reports r ON u.id = r.reported_user_id 
                AND r.report_type = 'fake_account'
                AND r.status = 'pending'
            WHERE u.trust_score < 40 
               OR u.profile_score < 30
               OR (u.friend_count > 100 AND u.account_age_days < 7)
               OR u.post_count = 0
            GROUP BY u.id
            ORDER BY u.trust_score ASC, report_count DESC
            LIMIT 50
        `);
        
        res.json({ accounts });
        
    } catch (error) {
        console.error('Get fake accounts error:', error);
        res.status(500).json({ error: 'Failed to get fake accounts' });
    }
});

app.post('/api/admin/ban-user', authenticateAdmin, async (req, res) => {
    try {
        const { userId, reason } = req.body;
        const adminId = req.admin.id;
        
        await db.execute(
            'UPDATE users SET active_status = ? WHERE id = ?',
            ['banned', userId]
        );
        
        // Create admin action log
        await db.execute(`
            INSERT INTO admin_actions 
            (admin_id, action_type, target_type, target_id, details) 
            VALUES (?, 'ban_user', 'user', ?, ?)
        `, [adminId, userId, JSON.stringify({ reason })]);
        
        res.json({ message: 'User banned successfully' });
        
    } catch (error) {
        console.error('Ban user error:', error);
        res.status(500).json({ error: 'Failed to ban user' });
    }
});

// 11. BIRTHDAY SYSTEM
app.get('/api/birthdays/upcoming', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [birthdays] = await db.execute(`
            SELECT 
                u.id, u.full_name, u.avatar_url,
                b.birth_date,
                DAYOFYEAR(b.birth_date) - DAYOFYEAR(NOW()) as days_until
            FROM birthdays b
            JOIN users u ON b.user_id = u.id
            JOIN friendships f ON u.id = f.friend_id
            WHERE f.user_id = ? 
              AND f.status = 'accepted'
              AND b.is_public = TRUE
              AND DAYOFYEAR(b.birth_date) >= DAYOFYEAR(NOW())
              AND DAYOFYEAR(b.birth_date) <= DAYOFYEAR(NOW()) + 30
            ORDER BY days_until ASC
            LIMIT 20
        `, [userId]);
        
        res.json({ birthdays });
        
    } catch (error) {
        console.error('Get birthdays error:', error);
        res.status(500).json({ error: 'Failed to get birthdays' });
    }
});

app.post('/api/birthdays/wish', authenticateToken, async (req, res) => {
    try {
        const { birthdayUserId, message, giftType } = req.body;
        const wisherId = req.user.id;
        
        await db.execute(`
            INSERT INTO birthday_wishes 
            (birthday_user_id, wisher_id, message, gift_type) 
            VALUES (?, ?, ?, ?)
        `, [birthdayUserId, wisherId, message, giftType || 'cake']);
        
        // Create notification
        await db.execute(`
            INSERT INTO notifications 
            (user_id, type, title, message, related_id, related_type) 
            VALUES (?, 'birthday', 'Birthday Wish', 
            '? sent you a birthday wish', ?, 'user')
        `, [birthdayUserId, req.user.full_name || req.user.username, wisherId]);
        
        res.json({ message: 'Birthday wish sent successfully' });
        
    } catch (error) {
        console.error('Send wish error:', error);
        res.status(500).json({ error: 'Failed to send birthday wish' });
    }
});

// 12. NOTIFICATIONS
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [notifications] = await db.execute(`
            SELECT 
                n.*,
                u.avatar_url as sender_avatar,
                u.full_name as sender_name
            FROM notifications n
            LEFT JOIN users u ON n.related_id = u.id AND n.related_type = 'user'
            WHERE n.user_id = ?
            ORDER BY n.created_at DESC
            LIMIT 50
        `, [userId]);
        
        // Mark as read
        await db.execute(
            `UPDATE notifications SET is_read = TRUE, read_at = NOW() 
            WHERE user_id = ? AND is_read = FALSE`,
            [userId]
        );
        
        res.json({ notifications });
        
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ error: 'Failed to get notifications' });
    }
});

// 13. THEMES & UI SETTINGS
app.put('/api/settings/theme', authenticateToken, async (req, res) => {
    try {
        const { theme, glassmorphism, animations } = req.body;
        const userId = req.user.id;
        
        await db.execute(`
            UPDATE user_settings 
            SET theme = ?, glassmorphism = ?, animations = ?
            WHERE user_id = ?
        `, [theme, glassmorphism, animations, userId]);
        
        res.json({ message: 'Theme updated successfully' });
        
    } catch (error) {
        console.error('Update theme error:', error);
        res.status(500).json({ error: 'Failed to update theme' });
    }
});

// 14. DIGITAL ID CARD
app.get('/api/digital-id/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        
        const [ids] = await db.execute(`
            SELECT 
                d.*,
                u.full_name, u.username, u.avatar_url,
                u.is_verified, u.created_at as member_since
            FROM digital_ids d
            JOIN users u ON d.user_id = u.id
            WHERE u.id = ? OR u.public_id = ?
        `, [userId, userId]);
        
        if (ids.length === 0) {
            return res.status(404).json({ error: 'Digital ID not found' });
        }
        
        // Update shares count
        await db.execute(
            'UPDATE digital_ids SET shares_count = shares_count + 1 WHERE id = ?',
            [ids[0].id]
        );
        
        res.json({ digitalId: ids[0] });
        
    } catch (error) {
        console.error('Get digital ID error:', error);
        res.status(500).json({ error: 'Failed to get digital ID' });
    }
});

// 15. ANALYTICS
app.get('/api/admin/analytics', authenticateAdmin, async (req, res) => {
    try {
        const [analytics] = await db.execute(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as new_users,
                COUNT(CASE WHEN last_seen >= DATE_SUB(NOW(), INTERVAL 1 DAY) THEN 1 END) as active_users
            FROM users
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        `);
        
        const [engagement] = await db.execute(`
            SELECT 
                'posts' as type, COUNT(*) as count FROM posts WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            UNION ALL
            SELECT 'likes', COUNT(*) FROM post_likes WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            UNION ALL
            SELECT 'comments', COUNT(*) FROM comments WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            UNION ALL
            SELECT 'messages', COUNT(*) FROM messages WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
        `);
        
        const [fakeAccounts] = await db.execute(`
            SELECT COUNT(*) as count FROM users 
            WHERE trust_score < 30 AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        `);
        
        res.json({
            analytics,
            engagement,
            fakeAccounts: fakeAccounts[0].count
        });
        
    } catch (error) {
        console.error('Get analytics error:', error);
        res.status(500).json({ error: 'Failed to get analytics' });
    }
});

// Serve uploads
app.use('/uploads', express.static('uploads'));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
