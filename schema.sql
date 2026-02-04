-- Main Database
CREATE DATABASE IF NOT EXISTS friendsconnect;
USE friendsconnect;

-- Users Table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    bio TEXT,
    profile_pic VARCHAR(500) DEFAULT 'default.jpg',
    cover_pic VARCHAR(500),
    birthdate DATE,
    gender ENUM('male', 'female', 'other') DEFAULT 'other',
    phone VARCHAR(20),
    country VARCHAR(50),
    city VARCHAR(50),
    is_verified BOOLEAN DEFAULT FALSE,
    is_online BOOLEAN DEFAULT FALSE,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    privacy_level ENUM('public', 'friends', 'private') DEFAULT 'public',
    friend_privacy ENUM('everyone', 'friends_of_friends', 'no_one') DEFAULT 'everyone',
    theme_preference ENUM('light', 'dark', 'blue', 'purple', 'gold') DEFAULT 'dark',
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    account_status ENUM('active', 'suspended', 'banned') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_online (is_online)
);

-- Friends System
CREATE TABLE friend_requests (
    id INT PRIMARY KEY AUTO_INCREMENT,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    status ENUM('pending', 'accepted', 'rejected', 'blocked') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_request (sender_id, receiver_id),
    INDEX idx_sender (sender_id),
    INDEX idx_receiver (receiver_id)
);

CREATE TABLE friendships (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user1_id INT NOT NULL,
    user2_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_friendship (user1_id, user2_id),
    INDEX idx_user1 (user1_id),
    INDEX idx_user2 (user2_id)
);

CREATE TABLE blocked_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    blocker_id INT NOT NULL,
    blocked_id INT NOT NULL,
    reason VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (blocker_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (blocked_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_block (blocker_id, blocked_id)
);

-- Posts System
CREATE TABLE posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    content TEXT,
    post_type ENUM('text', 'image', 'video', 'album') DEFAULT 'text',
    privacy ENUM('public', 'friends', 'only_me', 'custom') DEFAULT 'public',
    location VARCHAR(255),
    feeling VARCHAR(100),
    tagged_users JSON,
    view_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_created (created_at),
    FULLTEXT idx_content (content)
);

CREATE TABLE post_media (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    media_url VARCHAR(500) NOT NULL,
    media_type ENUM('image', 'video', 'audio') NOT NULL,
    thumbnail_url VARCHAR(500),
    order_index INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    INDEX idx_post (post_id)
);

CREATE TABLE post_reactions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    reaction_type ENUM('like', 'love', 'haha', 'wow', 'sad', 'angry') DEFAULT 'like',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_reaction (post_id, user_id),
    INDEX idx_post (post_id)
);

CREATE TABLE comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    parent_id INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES comments(id) ON DELETE CASCADE,
    INDEX idx_post (post_id),
    INDEX idx_user (user_id)
);

CREATE TABLE comment_reactions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    comment_id INT NOT NULL,
    user_id INT NOT NULL,
    reaction_type ENUM('like', 'love') DEFAULT 'like',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_comment_reaction (comment_id, user_id)
);

CREATE TABLE shares (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_post (post_id),
    INDEX idx_user (user_id)
);

CREATE TABLE saved_posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    post_id INT NOT NULL,
    folder VARCHAR(100) DEFAULT 'general',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    UNIQUE KEY unique_save (user_id, post_id)
);

-- Stories
CREATE TABLE stories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    media_url VARCHAR(500) NOT NULL,
    media_type ENUM('image', 'video') NOT NULL,
    text_content VARCHAR(500),
    bg_color VARCHAR(50),
    font_style VARCHAR(50),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
);

CREATE TABLE story_views (
    id INT PRIMARY KEY AUTO_INCREMENT,
    story_id INT NOT NULL,
    viewer_id INT NOT NULL,
    viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (story_id) REFERENCES stories(id) ON DELETE CASCADE,
    FOREIGN KEY (viewer_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_view (story_id, viewer_id)
);

-- Chat & Messaging
CREATE TABLE conversations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    conversation_type ENUM('private', 'group') DEFAULT 'private',
    name VARCHAR(100),
    group_photo VARCHAR(500),
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE conversation_participants (
    id INT PRIMARY KEY AUTO_INCREMENT,
    conversation_id INT NOT NULL,
    user_id INT NOT NULL,
    role ENUM('admin', 'moderator', 'member') DEFAULT 'member',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_participant (conversation_id, user_id)
);

CREATE TABLE messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    conversation_id INT NOT NULL,
    sender_id INT NOT NULL,
    content TEXT,
    message_type ENUM('text', 'image', 'video', 'audio', 'file') DEFAULT 'text',
    media_url VARCHAR(500),
    replied_to INT,
    is_edited BOOLEAN DEFAULT FALSE,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (replied_to) REFERENCES messages(id) ON DELETE SET NULL,
    INDEX idx_conversation (conversation_id),
    INDEX idx_sender (sender_id)
);

CREATE TABLE message_reads (
    id INT PRIMARY KEY AUTO_INCREMENT,
    message_id INT NOT NULL,
    user_id INT NOT NULL,
    read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_read (message_id, user_id)
);

CREATE TABLE typing_indicators (
    id INT PRIMARY KEY AUTO_INCREMENT,
    conversation_id INT NOT NULL,
    user_id INT NOT NULL,
    is_typing BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_typing (conversation_id, user_id)
);

-- Groups System
CREATE TABLE groups (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    group_photo VARCHAR(500),
    cover_photo VARCHAR(500),
    creator_id INT NOT NULL,
    privacy ENUM('public', 'private', 'secret') DEFAULT 'public',
    rules TEXT,
    member_count INT DEFAULT 1,
    post_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_creator (creator_id)
);

CREATE TABLE group_members (
    id INT PRIMARY KEY AUTO_INCREMENT,
    group_id INT NOT NULL,
    user_id INT NOT NULL,
    role ENUM('admin', 'moderator', 'member') DEFAULT 'member',
    status ENUM('pending', 'approved', 'banned') DEFAULT 'pending',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_membership (group_id, user_id)
);

CREATE TABLE group_posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    group_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT,
    post_type ENUM('text', 'image', 'video', 'poll') DEFAULT 'text',
    media_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_group (group_id)
);

-- Notifications
CREATE TABLE notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    type ENUM('friend_request', 'friend_accept', 'like', 'comment', 
              'mention', 'birthday', 'group_invite', 'message', 'marketplace') NOT NULL,
    sender_id INT,
    post_id INT,
    comment_id INT,
    group_id INT,
    conversation_id INT,
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_unread (user_id, is_read)
);

-- Birthdays
CREATE TABLE birthday_wishes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    birthday_user_id INT NOT NULL,
    sender_id INT NOT NULL,
    message TEXT NOT NULL,
    gift_type ENUM('cake', 'balloon', 'gift', 'heart') DEFAULT 'cake',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (birthday_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_birthday_user (birthday_user_id)
);

-- Fake Account Detection
CREATE TABLE user_reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    reporter_id INT NOT NULL,
    reported_user_id INT NOT NULL,
    report_type ENUM('fake', 'spam', 'harassment', 'inappropriate', 'other') NOT NULL,
    description TEXT,
    evidence JSON,
    status ENUM('pending', 'reviewing', 'resolved', 'dismissed') DEFAULT 'pending',
    resolved_by INT,
    resolved_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reported_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE suspicious_activities (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    activity_type ENUM('multiple_requests', 'spam_messages', 'no_profile', 
                      'no_posts', 'same_ip', 'unusual_login') NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    risk_score INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id)
);

-- Marketplace (if needed)
CREATE TABLE marketplace_items (
    id INT PRIMARY KEY AUTO_INCREMENT,
    seller_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(100),
    condition ENUM('new', 'like_new', 'good', 'fair', 'poor') DEFAULT 'good',
    images JSON,
    location VARCHAR(255),
    status ENUM('available', 'pending', 'sold', 'hidden') DEFAULT 'available',
    view_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_seller (seller_id),
    FULLTEXT idx_title_description (title, description)
);

-- Account Security
CREATE TABLE login_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    device_type VARCHAR(50),
    location VARCHAR(100),
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP NULL,
    is_successful BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_login_time (login_time)
);

CREATE TABLE email_verifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    email VARCHAR(100) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_otp (otp_code),
    INDEX idx_user (user_id)
);

CREATE TABLE password_resets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user (user_id)
);

CREATE TABLE sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    session_token VARCHAR(255) NOT NULL,
    device_info TEXT,
    ip_address VARCHAR(45),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_token (session_token),
    INDEX idx_user (user_id)
);

-- Admin System
CREATE TABLE admins (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    role ENUM('super_admin', 'admin', 'moderator') DEFAULT 'moderator',
    permissions JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_admin (user_id)
);

CREATE TABLE admin_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    admin_id INT NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_type ENUM('user', 'post', 'group', 'comment', 'report') NOT NULL,
    target_id INT NOT NULL,
    details JSON,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
);

-- Digital ID Card
CREATE TABLE user_qr_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    qr_code_data VARCHAR(500) NOT NULL,
    qr_code_image VARCHAR(500),
    shareable_link VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_qr (user_id)
);

-- Create stored procedures for common operations
DELIMITER $$

CREATE PROCEDURE GetMutualFriends(IN user1_id INT, IN user2_id INT)
BEGIN
    SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online
    FROM friendships f1
    JOIN friendships f2 ON f1.user2_id = f2.user2_id
    JOIN users u ON f1.user2_id = u.id
    WHERE f1.user1_id = user1_id 
      AND f2.user1_id = user2_id
      AND u.id NOT IN (user1_id, user2_id)
    UNION
    SELECT u.id, u.username, u.full_name, u.profile_pic, u.is_online
    FROM friendships f1
    JOIN friendships f2 ON f1.user2_id = f2.user1_id
    JOIN users u ON f1.user2_id = u.id
    WHERE f1.user1_id = user1_id 
      AND f2.user2_id = user2_id
      AND u.id NOT IN (user1_id, user2_id);
END$$

CREATE PROCEDURE GetFriendsFeed(IN user_id INT, IN offset_val INT, IN limit_val INT)
BEGIN
    SELECT p.*, u.username, u.full_name, u.profile_pic,
           COUNT(DISTINCT pr.id) as reaction_count,
           COUNT(DISTINCT c.id) as comment_count,
           EXISTS(SELECT 1 FROM post_reactions WHERE post_id = p.id AND user_id = user_id) as has_reacted,
           EXISTS(SELECT 1 FROM saved_posts WHERE post_id = p.id AND user_id = user_id) as is_saved
    FROM posts p
    JOIN users u ON p.user_id = u.id
    LEFT JOIN post_reactions pr ON p.id = pr.post_id
    LEFT JOIN comments c ON p.id = c.post_id AND c.parent_id IS NULL
    WHERE p.is_deleted = FALSE 
      AND (p.privacy = 'public' 
           OR (p.privacy = 'friends' AND EXISTS(
               SELECT 1 FROM friendships 
               WHERE (user1_id = user_id AND user2_id = p.user_id) 
                  OR (user1_id = p.user_id AND user2_id = user_id)
           ))
           OR p.user_id = user_id)
    GROUP BY p.id
    ORDER BY p.created_at DESC
    LIMIT limit_val OFFSET offset_val;
END$$

CREATE PROCEDURE UpdateUserOnlineStatus(IN user_id INT, IN is_online BOOLEAN)
BEGIN
    UPDATE users 
    SET is_online = is_online, 
        last_seen = CURRENT_TIMESTAMP 
    WHERE id = user_id;
END$$

CREATE PROCEDURE CheckFakeAccount(IN user_id INT)
BEGIN
    SELECT 
        (SELECT COUNT(*) FROM posts WHERE user_id = user_id) = 0 as has_no_posts,
        (SELECT profile_pic FROM users WHERE id = user_id) = 'default.jpg' as has_default_pic,
        (SELECT COUNT(*) FROM friend_requests WHERE sender_id = user_id AND created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)) > 50 as many_requests,
        (SELECT COUNT(DISTINCT ip_address) FROM login_history WHERE user_id = user_id) < 2 as few_ip_addresses,
        (SELECT COUNT(*) FROM user_reports WHERE reported_user_id = user_id AND status = 'pending') > 0 as has_reports;
END$$

DELIMITER ;

-- Insert default admin user (password: Admin123!)
INSERT INTO users (username, email, password_hash, full_name, is_verified, is_online) 
VALUES ('admin', 'admin@friendsconnect.com', '$2b$10$YourHashedPasswordHere', 'System Admin', TRUE, TRUE);

INSERT INTO admins (user_id, role, permissions) 
VALUES (LAST_INSERT_ID(), 'super_admin', '["all"]');
