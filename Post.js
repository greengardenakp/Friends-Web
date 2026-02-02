const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: [true, 'Post content is required'],
    maxlength: [5000, 'Post cannot exceed 5000 characters']
  },
  media_urls: [{
    type: String,
    validate: {
      validator: function(url) {
        return /^(http|https):\/\/.+/.test(url);
      },
      message: 'Invalid media URL'
    }
  }],
  privacy: {
    type: String,
    enum: ['public', 'friends', 'private'],
    default: 'friends'
  },
  location: {
    type: String
  },
  tagged_users: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  feelings: {
    type: String,
    enum: ['happy', 'sad', 'excited', 'angry', 'loved', 'bored', null],
    default: null
  },
  hashtags: [{
    type: String,
    lowercase: true
  }],
  is_edited: {
    type: Boolean,
    default: false
  },
  edited_at: {
    type: Date
  },
  is_deleted: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for likes count
postSchema.virtual('likeCount', {
  ref: 'Like',
  localField: '_id',
  foreignField: 'post',
  count: true
});

// Virtual for comments count
postSchema.virtual('commentCount', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'post',
  count: true
});

// Virtual for shares count
postSchema.virtual('shareCount', {
  ref: 'Share',
  localField: '_id',
  foreignField: 'post',
  count: true
});

// Index for better query performance
postSchema.index({ author: 1, createdAt: -1 });
postSchema.index({ hashtags: 1 });
postSchema.index({ createdAt: -1 });

const Post = mongoose.model('Post', postSchema);
module.exports = Post;
