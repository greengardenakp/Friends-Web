const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  post: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
    required: true
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: [true, 'Comment content is required'],
    maxlength: [1000, 'Comment cannot exceed 1000 characters']
  },
  media_url: {
    type: String
  },
  parent_comment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment',
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
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for likes count
commentSchema.virtual('likeCount', {
  ref: 'Like',
  localField: '_id',
  foreignField: 'comment',
  count: true
});

// Virtual for replies count
commentSchema.virtual('replyCount', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'parent_comment',
  count: true
});

const Comment = mongoose.model('Comment', commentSchema);
module.exports = Comment;
