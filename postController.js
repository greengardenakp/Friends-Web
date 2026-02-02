const Post = require('../models/Post');
const Comment = require('../models/Comment');
const Notification = require('../models/Notification');
const User = require('../models/User');
const Friend = require('../models/Friend');

// @desc    Create a post
// @route   POST /api/posts
// @access  Private
const createPost = async (req, res) => {
  try {
    const { content, privacy, location, feelings, hashtags } = req.body;
    
    const post = await Post.create({
      author: req.user._id,
      content,
      privacy: privacy || 'friends',
      location,
      feelings,
      hashtags: hashtags ? hashtags.split(',').map(tag => tag.trim().toLowerCase()) : []
    });

    // Handle media uploads
    if (req.files && req.files.length > 0) {
      post.media_urls = req.files.map(file => `/uploads/posts/${file.filename}`);
      await post.save();
    }

    // Populate author info
    await post.populate('author', 'full_name username avatar_url');

    res.status(201).json({ post });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Get feed posts
// @route   GET /api/posts/feed
// @access  Private
const getFeedPosts = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Get user's friends
    const friends = await Friend.find({
      $or: [{ user: req.user._id }, { friend: req.user._id }],
      status: 'accepted'
    });

    const friendIds = friends.map(f => 
      f.user.toString() === req.user._id.toString() ? f.friend : f.user
    );

    // Query posts
    const posts = await Post.find({
      $or: [
        { author: req.user._id },
        { 
          author: { $in: friendIds },
          privacy: { $in: ['friends', 'public'] }
        },
        { privacy: 'public' }
      ],
      is_deleted: false
    })
    .populate('author', 'full_name username avatar_url')
    .populate('tagged_users', 'full_name username avatar_url')
    .sort('-createdAt')
    .skip(skip)
    .limit(limit);

    // Get counts for each post
    const postsWithCounts = await Promise.all(posts.map(async (post) => {
      const postObj = post.toObject();
      
      // Check if user liked the post
      const like = await Like.findOne({
        post: post._id,
        user: req.user._id
      });
      
      postObj.liked = !!like;
      
      return postObj;
    }));

    res.json({ 
      posts: postsWithCounts,
      page,
      limit,
      hasMore: posts.length === limit
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Get trending posts
// @route   GET /api/posts/trending
// @access  Private
const getTrendingPosts = async (req, res) => {
  try {
    // Get posts from last 7 days with most engagement
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);

    const posts = await Post.aggregate([
      {
        $match: {
          createdAt: { $gte: weekAgo },
          is_deleted: false,
          privacy: { $in: ['public', 'friends'] }
        }
      },
      {
        $lookup: {
          from: 'likes',
          localField: '_id',
          foreignField: 'post',
          as: 'likes'
        }
      },
      {
        $lookup: {
          from: 'comments',
          localField: '_id',
          foreignField: 'post',
          as: 'comments'
        }
      },
      {
        $addFields: {
          engagementScore: {
            $add: [
              { $size: '$likes' },
              { $multiply: [{ $size: '$comments' }, 2] }
            ]
          }
        }
      },
      {
        $sort: { engagementScore: -1, createdAt: -1 }
      },
      {
        $limit: 10
      },
      {
        $lookup: {
          from: 'users',
          localField: 'author',
          foreignField: '_id',
          as: 'author'
        }
      },
      {
        $unwind: '$author'
      },
      {
        $project: {
          content: 1,
          media_urls: 1,
          'author.full_name': 1,
          'author.avatar_url': 1,
          like_count: { $size: '$likes' },
          comment_count: { $size: '$comments' },
          engagementScore: 1,
          createdAt: 1
        }
      }
    ]);

    res.json({ posts });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Like a post
// @route   POST /api/posts/:id/like
// @access  Private
const likePost = async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.user._id;

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Check if already liked
    const existingLike = await Like.findOne({ post: postId, user: userId });
    
    if (existingLike) {
      // Unlike
      await existingLike.deleteOne();
      
      // Send notification
      if (!post.author.equals(userId)) {
        await Notification.deleteOne({
          recipient: post.author,
          sender: userId,
          type: 'post_like',
          target_id: postId
        });
      }
      
      return res.json({ liked: false, message: 'Post unliked' });
    }

    // Like
    const like = await Like.create({
      post: postId,
      user: userId
    });

    // Send notification to post author
    if (!post.author.equals(userId)) {
      const user = await User.findById(userId);
      
      await Notification.create({
        recipient: post.author,
        sender: userId,
        type: 'post_like',
        target_id: postId,
        message: `${user.full_name} liked your post`
      });
    }

    res.json({ liked: true, message: 'Post liked' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Add comment to post
// @route   POST /api/posts/:id/comments
// @access  Private
const addComment = async (req, res) => {
  try {
    const { content, parent_comment } = req.body;
    const postId = req.params.id;

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const comment = await Comment.create({
      post: postId,
      author: req.user._id,
      content,
      parent_comment: parent_comment || null
    });

    // Populate author info
    await comment.populate('author', 'full_name username avatar_url');

    // Send notification to post author
    if (!post.author.equals(req.user._id)) {
      await Notification.create({
        recipient: post.author,
        sender: req.user._id,
        type: 'post_comment',
        target_id: postId,
        message: `${req.user.full_name} commented on your post`
      });
    }

    // Send notification to parent comment author if it's a reply
    if (parent_comment) {
      const parentComment = await Comment.findById(parent_comment);
      if (parentComment && !parentComment.author.equals(req.user._id)) {
        await Notification.create({
          recipient: parentComment.author,
          sender: req.user._id,
          type: 'comment_reply',
          target_id: comment._id,
          message: `${req.user.full_name} replied to your comment`
        });
      }
    }

    res.status(201).json({ comment });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Share a post
// @route   POST /api/posts/:id/share
// @access  Private
const sharePost = async (req, res) => {
  try {
    const postId = req.params.id;
    const { content, privacy } = req.body;

    const originalPost = await Post.findById(postId);
    if (!originalPost) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Create share record
    const share = await Share.create({
      original_post: postId,
      shared_by: req.user._id,
      content: content || '',
      privacy: privacy || 'friends'
    });

    // Update share count on original post
    originalPost.share_count = (originalPost.share_count || 0) + 1;
    await originalPost.save();

    // Send notification to original post author
    if (!originalPost.author.equals(req.user._id)) {
      await Notification.create({
        recipient: originalPost.author,
        sender: req.user._id,
        type: 'post_share',
        target_id: postId,
        message: `${req.user.full_name} shared your post`
      });
    }

    res.json({ share, message: 'Post shared successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Delete post
// @route   DELETE /api/posts/:id
// @access  Private
const deletePost = async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Check if user owns the post
    if (!post.author.equals(req.user._id)) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    // Soft delete
    post.is_deleted = true;
    await post.save();

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  createPost,
  getFeedPosts,
  getTrendingPosts,
  likePost,
  addComment,
  sharePost,
  deletePost
};
