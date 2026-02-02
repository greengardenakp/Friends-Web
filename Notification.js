const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: [
      'friend_request',
      'friend_accept',
      'post_like',
      'post_comment',
      'post_share',
      'comment_like',
      'comment_reply',
      'message',
      'birthday',
      'system'
    ],
    required: true
  },
  target_type: {
    type: String,
    enum: ['post', 'comment', 'friend', 'message', 'story', null],
    default: null
  },
  target_id: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'target_type'
  },
  message: {
    type: String,
    required: true
  },
  is_read: {
    type: Boolean,
    default: false
  },
  read_at: {
    type: Date
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  }
}, {
  timestamps: true
});

// Index for faster queries
notificationSchema.index({ recipient: 1, is_read: 1, createdAt: -1 });
notificationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 }); // 30 days TTL

const Notification = mongoose.model('Notification', notificationSchema);
module.exports = Notification;
