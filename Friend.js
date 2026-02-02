const mongoose = require('mongoose');

const friendSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  friend: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected', 'blocked'],
    default: 'pending'
  },
  requested_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  accepted_at: {
    type: Date
  }
}, {
  timestamps: true
});

// Compound index to ensure unique friendship
friendSchema.index({ user: 1, friend: 1 }, { unique: true });

// Pre-save to ensure user < friend for consistency
friendSchema.pre('save', function(next) {
  if (this.user.toString() > this.friend.toString()) {
    [this.user, this.friend] = [this.friend, this.user];
  }
  next();
});

const Friend = mongoose.model('Friend', friendSchema);
module.exports = Friend;
