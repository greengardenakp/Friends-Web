const mongoose = require('mongoose');

const storySchema = new mongoose.Schema({
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  media_url: {
    type: String,
    required: true
  },
  media_type: {
    type: String,
    enum: ['image', 'video'],
    required: true
  },
  caption: {
    type: String,
    maxlength: [2200, 'Caption cannot exceed 2200 characters']
  },
  location: {
    type: String
  },
  tagged_users: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  viewers: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    viewed_at: {
      type: Date,
      default: Date.now
    }
  }],
  view_count: {
    type: Number,
    default: 0
  },
  expires_at: {
    type: Date,
    default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from creation
  },
  is_archived: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// TTL index for automatic deletion after expiration
storySchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

// Index for better query performance
storySchema.index({ author: 1, createdAt: -1 });
storySchema.index({ expires_at: 1 });

const Story = mongoose.model('Story', storySchema);
module.exports = Story;
