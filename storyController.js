const Story = require('../models/Story');
const Notification = require('../models/Notification');

// @desc    Create a story
// @route   POST /api/stories
// @access  Private
const createStory = async (req, res) => {
  try {
    const { caption, location } = req.body;

    if (!req.file) {
      return res.status(400).json({ message: 'Media file is required' });
    }

    const mediaType = req.file.mimetype.startsWith('video/') ? 'video' : 'image';
    const mediaUrl = `/uploads/stories/${req.file.filename}`;

    const story = await Story.create({
      author: req.user._id,
      media_url: mediaUrl,
      media_type: mediaType,
      caption,
      location,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    });

    // Notify followers about new story
    // Implementation depends on your follower/friend system

    res.status(201).json({ 
      story,
      message: 'Story created successfully. It will expire in 24 hours.' 
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Get user's stories
// @route   GET /api/stories/me
// @access  Private
const getMyStories = async (req, res) => {
  try {
    const stories = await Story.find({
      author: req.user._id,
      expires_at: { $gt: new Date() },
      is_archived: false
    })
    .sort('-createdAt')
    .populate('author', 'full_name username avatar_url');

    res.json({ stories });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Get friends' stories
// @route   GET /api/stories/feed
// @access  Private
const getStoriesFeed = async (req, res) => {
  try {
    // Get user's friends (simplified - you need to implement friend system)
    const friends = []; // Get from friend controller
    
    const friendIds = [req.user._id, ...friends];

    const stories = await Story.find({
      author: { $in: friendIds },
      expires_at: { $gt: new Date() },
      is_archived: false
    })
    .sort('-createdAt')
    .populate('author', 'full_name username avatar_url');

    // Group stories by author
    const groupedStories = stories.reduce((acc, story) => {
      const authorId = story.author._id.toString();
      if (!acc[authorId]) {
        acc[authorId] = {
          author: story.author,
          stories: []
        };
      }
      acc[authorId].stories.push(story);
      return acc;
    }, {});

    res.json({ stories: Object.values(groupedStories) });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    View a story
// @route   POST /api/stories/:id/view
// @access  Private
const viewStory = async (req, res) => {
  try {
    const storyId = req.params.id;

    const story = await Story.findById(storyId);
    if (!story) {
      return res.status(404).json({ message: 'Story not found' });
    }

    // Check if already viewed
    const alreadyViewed = story.viewers.some(
      viewer => viewer.user.toString() === req.user._id.toString()
    );

    if (!alreadyViewed) {
      story.viewers.push({
        user: req.user._id,
        viewed_at: new Date()
      });
      story.view_count += 1;
      await story.save();
    }

    res.json({ message: 'Story viewed' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Archive a story
// @route   POST /api/stories/:id/archive
// @access  Private
const archiveStory = async (req, res) => {
  try {
    const storyId = req.params.id;

    const story = await Story.findById(storyId);
    if (!story) {
      return res.status(404).json({ message: 'Story not found' });
    }

    // Check if user owns the story
    if (!story.author.equals(req.user._id)) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    story.is_archived = true;
    await story.save();

    res.json({ message: 'Story archived' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Delete a story
// @route   DELETE /api/stories/:id
// @access  Private
const deleteStory = async (req, res) => {
  try {
    const storyId = req.params.id;

    const story = await Story.findById(storyId);
    if (!story) {
      return res.status(404).json({ message: 'Story not found' });
    }

    // Check if user owns the story
    if (!story.author.equals(req.user._id)) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    await story.deleteOne();

    res.json({ message: 'Story deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  createStory,
  getMyStories,
  getStoriesFeed,
  viewStory,
  archiveStory,
  deleteStory
};
