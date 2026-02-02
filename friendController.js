const Friend = require('../models/Friend');
const User = require('../models/User');
const Notification = require('../models/Notification');

// @desc    Send friend request
// @route   POST /api/friends/request
// @access  Private
const sendFriendRequest = async (req, res) => {
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
          : existingRequest.status === 'accepted' 
            ? 'Already friends' 
            : 'Request was previously rejected'
      });
    }

    // Create friend request
    const friendRequest = await Friend.create({
      user: req.user._id,
      friend: friendId,
      requested_by: req.user._id,
      status: 'pending'
    });

    // Send notification
    await Notification.create({
      recipient: friendId,
      sender: req.user._id,
      type: 'friend_request',
      message: `${req.user.full_name} sent you a friend request`
    });

    res.status(201).json({ 
      message: 'Friend request sent',
      friendRequest 
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Accept friend request
// @route   POST /api/friends/request/:requestId/accept
// @access  Private
const acceptFriendRequest = async (req, res) => {
  try {
    const requestId = req.params.requestId;

    const friendRequest = await Friend.findById(requestId);
    if (!friendRequest) {
      return res.status(404).json({ message: 'Friend request not found' });
    }

    // Check if user is the recipient
    if (!friendRequest.friend.equals(req.user._id)) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    // Update status
    friendRequest.status = 'accepted';
    friendRequest.accepted_at = new Date();
    await friendRequest.save();

    // Send notification to requester
    await Notification.create({
      recipient: friendRequest.user,
      sender: req.user._id,
      type: 'friend_accept',
      message: `${req.user.full_name} accepted your friend request`
    });

    res.json({ 
      message: 'Friend request accepted',
      friendRequest 
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Get friend suggestions
// @route   GET /api/friends/suggestions
// @access  Private
const getFriendSuggestions = async (req, res) => {
  try {
    // Get user's friends
    const friends = await Friend.find({
      $or: [{ user: req.user._id }, { friend: req.user._id }],
      status: 'accepted'
    }).select('user friend');

    const friendIds = friends.map(f => 
      f.user.toString() === req.user._id.toString() ? f.friend.toString() : f.user.toString()
    );

    // Get friends of friends
    const friendsOfFriends = await Friend.find({
      $or: [
        { user: { $in: friendIds } },
        { friend: { $in: friendIds } }
      ],
      status: 'accepted'
    }).select('user friend');

    // Collect potential suggestions
    const suggestionIds = new Set();
    friendsOfFriends.forEach(f => {
      const otherUser = f.user.toString() === req.user._id.toString() ? f.friend.toString() : f.user.toString();
      if (!friendIds.includes(otherUser) && otherUser !== req.user._id.toString()) {
        suggestionIds.add(otherUser);
      }
    });

    // Get users with similar interests (simplified)
    const currentUser = await User.findById(req.user._id);
    const similarUsers = await User.find({
      _id: { $nin: [...friendIds, req.user._id] },
      $or: [
        { location: currentUser.location },
        { bio: { $regex: new RegExp(currentUser.bio.split(' ').slice(0, 3).join('|'), 'i') } }
      ]
    }).limit(10 - suggestionIds.size);

    similarUsers.forEach(user => suggestionIds.add(user._id.toString()));

    // Get full user data for suggestions
    const suggestions = await User.find({
      _id: { $in: Array.from(suggestionIds) }
    })
    .select('full_name username avatar_url bio')
    .limit(10);

    // Add mutual friends count
    const suggestionsWithMutuals = await Promise.all(suggestions.map(async (user) => {
      const mutualFriends = await Friend.find({
        $or: [
          { user: user._id, friend: { $in: friendIds }, status: 'accepted' },
          { friend: user._id, user: { $in: friendIds }, status: 'accepted' }
        ]
      }).countDocuments();

      return {
        ...user.toObject(),
        mutual_friends_count: mutualFriends
      };
    }));

    // Sort by mutual friends count
    suggestionsWithMutuals.sort((a, b) => b.mutual_friends_count - a.mutual_friends_count);

    res.json({ suggestions: suggestionsWithMutuals });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Get online friends
// @route   GET /api/friends/online
// @access  Private
const getOnlineFriends = async (req, res) => {
  try {
    const friends = await Friend.find({
      $or: [{ user: req.user._id }, { friend: req.user._id }],
      status: 'accepted'
    });

    const friendIds = friends.map(f => 
      f.user.toString() === req.user._id.toString() ? f.friend : f.user
    );

    const onlineFriends = await User.find({
      _id: { $in: friendIds },
      online_status: 'online'
    })
    .select('full_name username avatar_url online_status last_seen');

    res.json({ friends: onlineFriends });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Get user's friends
// @route   GET /api/friends
// @access  Private
const getFriends = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const friends = await Friend.find({
      $or: [{ user: req.user._id }, { friend: req.user._id }],
      status: 'accepted'
    })
    .populate('user', 'full_name username avatar_url')
    .populate('friend', 'full_name username avatar_url')
    .skip(skip)
    .limit(limit);

    // Transform to get friend objects
    const friendsList = friends.map(f => {
      const friend = f.user._id.toString() === req.user._id.toString() ? f.friend : f.user;
      return {
        ...friend.toObject(),
        friendship_date: f.accepted_at
      };
    });

    const total = await Friend.countDocuments({
      $or: [{ user: req.user._id }, { friend: req.user._id }],
      status: 'accepted'
    });

    res.json({
      friends: friendsList,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Remove friend
// @route   DELETE /api/friends/:friendId
// @access  Private
const removeFriend = async (req, res) => {
  try {
    const { friendId } = req.params;

    const friendship = await Friend.findOneAndDelete({
      $or: [
        { user: req.user._id, friend: friendId },
        { user: friendId, friend: req.user._id }
      ],
      status: 'accepted'
    });

    if (!friendship) {
      return res.status(404).json({ message: 'Friendship not found' });
    }

    res.json({ message: 'Friend removed successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  sendFriendRequest,
  acceptFriendRequest,
  getFriendSuggestions,
  getOnlineFriends,
  getFriends,
  removeFriend
};
