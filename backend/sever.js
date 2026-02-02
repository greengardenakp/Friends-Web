const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('fs');

dotenv.config();

const app = express();

// Middleware
app.use(cors({
    origin: ['http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static('public/uploads'));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/friendsconnect', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    full_name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar_url: { type: String, default: '' },
    bio: { type: String, default: '' },
    online_status: { type: String, default: 'offline' },
    created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new mongoose.Schema({
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    media_urls: [{ type: String }],
    privacy: { type: String, default: 'friends' },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{
        author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        content: String,
        created_at: { type: Date, default: Date.now }
    }],
    created_at: { type: Date, default: Date.now }
});

const Post = mongoose.model('Post', postSchema);

// Friend Schema
const friendSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    friend: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
    created_at: { type: Date, default: Date.now }
});

const Friend = mongoose.model('Friend', friendSchema);

// Authentication middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            throw new Error();
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'friendsconnect_secret');
        const user = await User.findById(decoded.id);
        
        if (!user) {
            throw new Error();
        }
        
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Please authenticate' });
    }
};

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { full_name, username, email, password } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ 
                message: existingUser.email === email ? 'Email already exists' : 'Username already taken' 
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            full_name,
            username,
            email,
            password: hashedPassword
        });
        
        await user.save();
        
        // Generate token
        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET || 'friendsconnect_secret',
            { expiresIn: '30d' }
        );
        
        res.status(201).json({
            _id: user._id,
            full_name: user.full_name,
            username: user.username,
            email: user.email,
            avatar_url: user.avatar_url,
            bio: user.bio,
            token
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        
        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        
        // Update online status
        user.online_status = 'online';
        await user.save();
        
        // Generate token
        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET || 'friendsconnect_secret',
            { expiresIn: '30d' }
        );
        
        res.json({
            _id: user._id,
            full_name: user.full_name,
            username: user.username,
            email: user.email,
            avatar_url: user.avatar_url,
            bio: user.bio,
            online_status: user.online_status,
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password');
        res.json({ user });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Logout
app.post('/api/auth/logout', auth, async (req, res) => {
    try {
        req.user.online_status = 'offline';
        await req.user.save();
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update profile
app.put('/api/auth/profile', auth, async (req, res) => {
    try {
        const { bio } = req.body;
        
        req.user.bio = bio || req.user.bio;
        await req.user.save();
        
        res.json({
            _id: req.user._id,
            full_name: req.user.full_name,
            username: req.user.username,
            email: req.user.email,
            avatar_url: req.user.avatar_url,
            bio: req.user.bio
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update online status
app.put('/api/users/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
        req.user.online_status = status || 'online';
        await req.user.save();
        res.json({ message: 'Status updated' });
    } catch (error) {
        console.error('Status update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Search users
app.get('/api/users/search', auth, async (req, res) => {
    try {
        const { q } = req.query;
        const users = await User.find({
            $or: [
                { full_name: { $regex: q, $options: 'i' } },
                { username: { $regex: q, $options: 'i' } }
            ],
            _id: { $ne: req.user._id }
        }).select('full_name username avatar_url').limit(10);
        
        res.json({ users });
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get user by ID
app.get('/api/users/:id', auth, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ user });
    } catch (error) {
        console.error('Get user by ID error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create post
const upload = multer({ dest: 'public/uploads/' });
app.post('/api/posts', auth, upload.array('post_media', 10), async (req, res) => {
    try {
        const { content, privacy } = req.body;
        
        const post = new Post({
            author: req.user._id,
            content,
            privacy: privacy || 'friends',
            media_urls: req.files ? req.files.map(file => `/uploads/${file.filename}`) : []
        });
        
        await post.save();
        
        // Populate author info
        await post.populate('author', 'full_name username avatar_url');
        
        res.status(201).json({ post });
    } catch (error) {
        console.error('Create post error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get feed posts
app.get('/api/posts/feed', auth, async (req, res) => {
    try {
        const posts = await Post.find({
            $or: [
                { author: req.user._id },
                { privacy: 'public' },
                { 
                    author: { $in: await getFriendIds(req.user._id) },
                    privacy: 'friends'
                }
            ]
        })
        .populate('author', 'full_name username avatar_url')
        .populate('comments.author', 'full_name username avatar_url')
        .sort('-created_at')
        .limit(20);
        
        // Add like status
        const postsWithLikes = posts.map(post => ({
            ...post.toObject(),
            liked: post.likes.includes(req.user._id),
            likeCount: post.likes.length,
            commentCount: post.comments.length
        }));
        
        res.json({ posts: postsWithLikes });
    } catch (error) {
        console.error('Get feed error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Like post
app.post('/api/posts/:id/like', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }
        
        const liked = post.likes.includes(req.user._id);
        
        if (liked) {
            // Unlike
            post.likes = post.likes.filter(id => !id.equals(req.user._id));
        } else {
            // Like
            post.likes.push(req.user._id);
        }
        
        await post.save();
        
        res.json({ liked: !liked });
    } catch (error) {
        console.error('Like post error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add comment
app.post('/api/posts/:id/comments', auth, async (req, res) => {
    try {
        const { content } = req.body;
        const post = await Post.findById(req.params.id);
        
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }
        
        const comment = {
            author: req.user._id,
            content
        };
        
        post.comments.push(comment);
        await post.save();
        
        // Populate author info
        const populatedComment = {
            ...comment,
            author: {
                _id: req.user._id,
                full_name: req.user.full_name,
                username: req.user.username,
                avatar_url: req.user.avatar_url
            }
        };
        
        res.status(201).json({ comment: populatedComment });
    } catch (error) {
        console.error('Add comment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Share post
app.post('/api/posts/:id/share', auth, async (req, res) => {
    try {
        const { content } = req.body;
        const originalPost = await Post.findById(req.params.id);
        
        if (!originalPost) {
            return res.status(404).json({ message: 'Post not found' });
        }
        
        const sharePost = new Post({
            author: req.user._id,
            content: content || 'Shared post',
            original_post: originalPost._id
        });
        
        await sharePost.save();
        
        res.json({ message: 'Post shared' });
    } catch (error) {
        console.error('Share post error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get trending posts
app.get('/api/posts/trending', auth, async (req, res) => {
    try {
        const posts = await Post.find({ privacy: 'public' })
            .populate('author', 'full_name username avatar_url')
            .sort('-created_at')
            .limit(10);
        
        const postsWithCounts = posts.map(post => ({
            ...post.toObject(),
            like_count: post.likes.length,
            comment_count: post.comments.length
        }));
        
        res.json({ posts: postsWithCounts });
    } catch (error) {
        console.error('Trending posts error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Send friend request
app.post('/api/friends/request', auth, async (req, res) => {
    try {
        const { friendId } = req.body;
        
        if (friendId === req.user._id.toString()) {
            return res.status(400).json({ message: 'Cannot send friend request to yourself' });
        }
        
        const friend = await User.findById(friendId);
        if (!friend) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Check if request already exists
        const existingRequest = await Friend.findOne({
            $or: [
                { user: req.user._id, friend: friendId },
                { user: friendId, friend: req.user._id }
            ]
        });
        
        if (existingRequest) {
            return res.status(400).json({ 
                message: existingRequest.status === 'pending' 
                    ? 'Friend request already sent' 
                    : 'Already friends or request was rejected'
            });
        }
        
        // Create friend request
        const friendRequest = new Friend({
            user: req.user._id,
            friend: friendId,
            status: 'pending'
        });
        
        await friendRequest.save();
        
        res.status(201).json({ 
            message: 'Friend request sent',
            friendRequest 
        });
    } catch (error) {
        console.error('Friend request error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Accept friend request
app.post('/api/friends/request/:requestId/accept', auth, async (req, res) => {
    try {
        const friendRequest = await Friend.findById(req.params.requestId);
        
        if (!friendRequest) {
            return res.status(404).json({ message: 'Friend request not found' });
        }
        
        // Check if user is the recipient
        if (!friendRequest.friend.equals(req.user._id)) {
            return res.status(403).json({ message: 'Not authorized' });
        }
        
        // Update status
        friendRequest.status = 'accepted';
        await friendRequest.save();
        
        res.json({ 
            message: 'Friend request accepted',
            friendRequest 
        });
    } catch (error) {
        console.error('Accept friend request error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get friend suggestions
app.get('/api/friends/suggestions', auth, async (req, res) => {
    try {
        // Get users who are not friends and not the current user
        const friends = await Friend.find({
            $or: [{ user: req.user._id }, { friend: req.user._id }],
            status: 'accepted'
        });
        
        const friendIds = friends.map(f => 
            f.user.equals(req.user._id) ? f.friend : f.user
        );
        
        // Add current user to exclude list
        friendIds.push(req.user._id);
        
        const suggestions = await User.find({
            _id: { $nin: friendIds }
        })
        .select('full_name username avatar_url bio')
        .limit(10);
        
        // Add mutual friends count (simplified)
        const suggestionsWithMutuals = suggestions.map(user => ({
            ...user.toObject(),
            mutual_friends_count: Math.floor(Math.random() * 10) // Mock data
        }));
        
        res.json({ suggestions: suggestionsWithMutuals });
    } catch (error) {
        console.error('Friend suggestions error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get online friends
app.get('/api/friends/online', auth, async (req, res) => {
    try {
        const friends = await Friend.find({
            $or: [{ user: req.user._id }, { friend: req.user._id }],
            status: 'accepted'
        });
        
        const friendIds = friends.map(f => 
            f.user.equals(req.user._id) ? f.friend : f.user
        );
        
        const onlineFriends = await User.find({
            _id: { $in: friendIds },
            online_status: 'online'
        })
        .select('full_name username avatar_url online_status');
        
        res.json({ friends: onlineFriends });
    } catch (error) {
        console.error('Online friends error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get notifications
app.get('/api/notifications', auth, async (req, res) => {
    try {
        // Mock notifications for now
        const notifications = [
            {
                _id: '1',
                sender_name: 'John Doe',
                sender_avatar: '',
                message: 'sent you a friend request',
                type: 'friend_request',
                created_at: new Date(Date.now() - 3600000) // 1 hour ago
            },
            {
                _id: '2',
                sender_name: 'Jane Smith',
                sender_avatar: '',
                message: 'liked your post',
                type: 'post_like',
                created_at: new Date(Date.now() - 7200000) // 2 hours ago
            }
        ];
        
        res.json({ notifications });
    } catch (error) {
        console.error('Notifications error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create story
app.post('/api/stories', auth, upload.single('story_media'), async (req, res) => {
    try {
        const { caption } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ message: 'Media file is required' });
        }
        
        const story = {
            _id: new mongoose.Types.ObjectId(),
            author: req.user,
            media_url: `/uploads/${req.file.filename}`,
            caption,
            created_at: new Date(),
            expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
        };
        
        res.status(201).json({ 
            story,
            message: 'Story created successfully' 
        });
    } catch (error) {
        console.error('Create story error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Helper function to get friend IDs
async function getFriendIds(userId) {
    const friends = await Friend.find({
        $or: [{ user: userId }, { friend: userId }],
        status: 'accepted'
    });
    
    return friends.map(f => 
        f.user.equals(userId) ? f.friend : f.user
    );
}

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Health check: http://localhost:${PORT}/health`);
    console.log(`🔗 API Base URL: http://localhost:${PORT}/api`);
});
