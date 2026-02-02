const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  chat: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Chat',
    required: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: true,
    maxlength: [5000, 'Message cannot exceed 5000 characters']
  },
  media_url: {
    type: String
  },
  media_type: {
    type: String,
    enum: ['image', 'video', 'audio', 'document', null],
    default: null
  },
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
  },
  deleted_at: {
    type: Date
  },
  read_by: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    read_at: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

const chatSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  is_group: {
    type: Boolean,
    default: false
  },
  group_name: {
    type: String
  },
  group_avatar: {
    type: String
  },
  group_admin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  last_message: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  is_archived: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    archived_at: {
      type: Date,
      default: Date.now
    }
  }],
  muted_by: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }]
}, {
  timestamps: true
});

// Ensure participants are unique and sorted
chatSchema.pre('save', function(next) {
  this.participants.sort();
  next();
});

// Compound index for unique chats between users
chatSchema.index({ participants: 1, is_group: 1 }, { unique: true });

const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);

module.exports = { Chat, Message };
