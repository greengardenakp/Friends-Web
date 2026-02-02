const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  full_name: {
    type: String,
    required: [true, 'Please enter your full name'],
    trim: true
  },
  username: {
    type: String,
    required: [true, 'Please enter a username'],
    unique: true,
    lowercase: true,
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Please enter your email'],
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: [true, 'Please enter a password'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  avatar_url: {
    type: String,
    default: 'https://res.cloudinary.com/demo/image/upload/v1570979186/avatar_placeholder.jpg'
  },
  bio: {
    type: String,
    maxlength: [250, 'Bio cannot exceed 250 characters'],
    default: ''
  },
  date_of_birth: {
    type: Date
  },
  gender: {
    type: String,
    enum: ['male', 'female', 'other', 'prefer-not-to-say']
  },
  location: {
    type: String,
    default: ''
  },
  online_status: {
    type: String,
    enum: ['online', 'offline', 'away'],
    default: 'offline'
  },
  last_seen: {
    type: Date,
    default: Date.now
  },
  privacy_settings: {
    profile_visibility: {
      type: String,
      enum: ['public', 'friends', 'private'],
      default: 'friends'
    },
    post_visibility: {
      type: String,
      enum: ['public', 'friends', 'private'],
      default: 'friends'
    }
  },
  is_verified: {
    type: Boolean,
    default: false
  },
  is_active: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Virtual for friend count
userSchema.virtual('friendCount', {
  ref: 'Friend',
  localField: '_id',
  foreignField: 'user',
  count: true
});

// Virtual for post count
userSchema.virtual('postCount', {
  ref: 'Post',
  localField: '_id',
  foreignField: 'author',
  count: true
});

const User = mongoose.model('User', userSchema);
module.exports = User;
