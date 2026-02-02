-- Create Database
CREATE DATABASE friendsconnect;
USE friendsconnect;

-- 1. Users Table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    avatar_url VARCHAR(500),
    cover_url VARCHAR(500),
    bio TEXT,
    location VARCHAR(100),
    interests JSON,
    birth_date DATE,
    gender ENUM('male', 'female', 'other'),
    phone VARCHAR(20),
    
    -- Security
    is_verified BOOLEAN DEFAULT FALSE,
    is_premium BOOLEAN DEFAULT FALSE,
    verification_code VARCHAR(10),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    
    -- Status
    online_status ENUM('online', 'offline', 'away') DEFAULT 'offline',
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active_status ENUM('active', 'suspended', 'banned') DEFAULT 'active',
    
    -- Fake Account Detection
    profile_score INT DEFAULT 100,
    trust_score INT DEFAULT 50,
    post_count INT DEFAULT 0,
    friend_count INT DEFAULT 0,
    account_age_days INT DEFAULT 0,
    
    -- Digital ID
    qr_code_url VARCHAR(500),
    profile_url VARCHAR(500),
    public_id VARCHAR(20) UNIQUE,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_email (email),
    INDEX idx_username (username),
    INDEX idx_location (location),
    INDEX idx_created_at (created_at)
);

-- 2. Friend System
CREATE TABLE friendships (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    friend_id INT NOT NULL,
    status ENUM('pending', 'accepted', 'rejected', 'blocked') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_friendship (user_id, friend_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_user_status (user_id, status),
    INDEX idx_friend_status (friend_id, status)
);

CREATE TABLE blocked_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    blocker_id INT NOT NULL,
    blocked_id INT NOT NULL,
    reason VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_block (blocker_id, blocked_id),
    FOREIGN KEY (blocker_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (blocked_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Posts System
CREATE TABLE posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    content TEXT,
    media_urls JSON,
    post_type ENUM('text', 'photo', 'video', 'poll') DEFAULT 'text',
    privacy ENUM('public', 'friends', 'only_me', 'custom') DEFAULT 'friends',
    location VARCHAR(100),
    tagged_users JSON,
    
    -- Engagement
    like_count INT DEFAULT 0,
    comment_count INT DEFAULT 0,
    share_count INT DEFAULT 0,
    view_count INT DEFAULT 0,
    save_count INT DEFAULT 0,
    
    -- Trending
    trending_score DECIMAL(10,2) DEFAULT 0,
    is_trending BOOLEAN DEFAULT FALSE,
    trending_until TIMESTAMP NULL,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_created (user_id, created_at),
    INDEX idx_trending (trending_score DESC),
    FULLTEXT idx_content (content)
);

CREATE TABLE post_likes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_like (post_id, user_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    parent_id INT NULL,
    content TEXT NOT NULL,
    like_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES comments(id) ON DELETE CASCADE,
    
    INDEX idx_post_created (post_id, created_at)
);

CREATE TABLE saved_posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    post_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_save (user_id, post_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

-- 4. Story System
CREATE TABLE stories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    media_url VARCHAR(500) NOT NULL,
    media_type ENUM('photo', 'video') NOT NULL,
    caption VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    view_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_expires (expires_at),
    INDEX idx_user_created (user_id, created_at DESC)
);

CREATE TABLE story_views (
    id INT PRIMARY KEY AUTO_INCREMENT,
    story_id INT NOT NULL,
    viewer_id INT NOT NULL,
    viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_story_view (story_id, viewer_id),
    FOREIGN KEY (story_id) REFERENCES stories(id) ON DELETE CASCADE,
    FOREIGN KEY (viewer_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 5. Messages System
CREATE TABLE conversations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    is_group BOOLEAN DEFAULT FALSE,
    group_name VARCHAR(100),
    group_avatar VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_created (created_at DESC)
);

CREATE TABLE conversation_members (
    id INT PRIMARY KEY AUTO_INCREMENT,
    conversation_id INT NOT NULL,
    user_id INT NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_admin BOOLEAN DEFAULT FALSE,
    
    UNIQUE KEY unique_member (conversation_id, user_id),
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    conversation_id INT NOT NULL,
    sender_id INT NOT NULL,
    message_type ENUM('text', 'image', 'video', 'voice', 'file') DEFAULT 'text',
    content TEXT,
    media_url VARCHAR(500),
    
    -- Read receipts
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP NULL,
    
    -- Typing indicator
    deleted BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_conversation_created (conversation_id, created_at DESC),
    INDEX idx_sender (sender_id),
    INDEX idx_unread (conversation_id, is_read, created_at)
);

-- 6. Groups System
CREATE TABLE groups (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    avatar_url VARCHAR(500),
    cover_url VARCHAR(500),
    creator_id INT NOT NULL,
    
    -- Settings
    privacy ENUM('public', 'private', 'secret') DEFAULT 'public',
    join_approval BOOLEAN DEFAULT FALSE,
    post_approval BOOLEAN DEFAULT FALSE,
    
    -- Stats
    member_count INT DEFAULT 1,
    post_count INT DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_privacy (privacy),
    FULLTEXT idx_group_search (name, description)
);

CREATE TABLE group_members (
    id INT PRIMARY KEY AUTO_INCREMENT,
    group_id INT NOT NULL,
    user_id INT NOT NULL,
    role ENUM('member', 'moderator', 'admin') DEFAULT 'member',
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'approved',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_group_member (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_user_groups (user_id, status)
);

CREATE TABLE group_posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    group_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT,
    media_urls JSON,
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'approved',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_group_status (group_id, status, created_at DESC)
);

-- 7. Birthday System
CREATE TABLE birthdays (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    birth_date DATE NOT NULL,
    is_public BOOLEAN DEFAULT TRUE,
    receive_wishes BOOLEAN DEFAULT TRUE,
    last_wished_year INT,
    
    UNIQUE KEY unique_user_birthday (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_upcoming (MONTH(birth_date), DAY(birth_date))
);

CREATE TABLE birthday_wishes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    birthday_user_id INT NOT NULL,
    wisher_id INT NOT NULL,
    message TEXT,
    gift_type ENUM('cake', 'gift', 'balloon', 'heart') DEFAULT 'cake',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (birthday_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (wisher_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_birthday_user (birthday_user_id, created_at DESC)
);

-- 8. Notifications System
CREATE TABLE notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    type ENUM(
        'friend_request',
        'friend_accepted',
        'like',
        'comment',
        'mention',
        'share',
        'birthday',
        'group_invite',
        'message',
        'warning'
    ) NOT NULL,
    
    title VARCHAR(100),
    message TEXT,
    related_id INT,
    related_type VARCHAR(50),
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP NULL,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_unread (user_id, is_read, created_at DESC),
    INDEX idx_user_type (user_id, type, created_at DESC)
);

-- 9. Marketplace
CREATE TABLE marketplace_items (
    id INT PRIMARY KEY AUTO_INCREMENT,
    seller_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    category VARCHAR(50),
    condition ENUM('new', 'like_new', 'good', 'fair') DEFAULT 'good',
    location VARCHAR(100),
    media_urls JSON,
    
    -- Status
    status ENUM('active', 'sold', 'reserved', 'expired') DEFAULT 'active',
    view_count INT DEFAULT 0,
    save_count INT DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_category_status (category, status),
    INDEX idx_seller (seller_id, status),
    FULLTEXT idx_marketplace_search (title, description, location)
);

CREATE TABLE marketplace_chats (
    id INT PRIMARY KEY AUTO_INCREMENT,
    item_id INT NOT NULL,
    buyer_id INT NOT NULL,
    seller_id INT NOT NULL,
    last_message TEXT,
    last_message_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unread_count INT DEFAULT 0,
    
    UNIQUE KEY unique_marketplace_chat (item_id, buyer_id, seller_id),
    FOREIGN KEY (item_id) REFERENCES marketplace_items(id) ON DELETE CASCADE,
    FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_user_chats (buyer_id, last_message_at DESC),
    INDEX idx_seller_chats (seller_id, last_message_at DESC)
);

-- 10. Fake Account Detection & Reports
CREATE TABLE reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    reporter_id INT NOT NULL,
    reported_user_id INT NULL,
    reported_post_id INT NULL,
    reported_group_id INT NULL,
    reported_item_id INT NULL,
    
    report_type ENUM(
        'fake_account',
        'harassment',
        'spam',
        'inappropriate_content',
        'scam',
        'other'
    ) NOT NULL,
    
    reason TEXT,
    evidence_urls JSON,
    status ENUM('pending', 'investigating', 'resolved', 'dismissed') DEFAULT 'pending',
    admin_notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reported_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (reported_post_id) REFERENCES posts(id) ON DELETE SET NULL,
    FOREIGN KEY (reported_group_id) REFERENCES groups(id) ON DELETE SET NULL,
    FOREIGN KEY (reported_item_id) REFERENCES marketplace_items(id) ON DELETE SET NULL,
    
    INDEX idx_status (status, created_at),
    INDEX idx_reported_user (reported_user_id, status)
);

CREATE TABLE login_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_type VARCHAR(50),
    location VARCHAR(100),
    success BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_logins (user_id, created_at DESC),
    INDEX idx_suspicious (ip_address, created_at)
);

-- 11. Admin System
CREATE TABLE admin_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('super_admin', 'admin', 'moderator') DEFAULT 'moderator',
    permissions JSON,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_role (role)
);

CREATE TABLE admin_actions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    admin_id INT NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    target_type VARCHAR(50),
    target_id INT,
    details JSON,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    INDEX idx_admin_actions (admin_id, created_at DESC)
);

-- 12. Themes & UI Settings
CREATE TABLE user_settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    
    -- UI Themes
    theme ENUM('light', 'dark', 'blue', 'purple', 'gold') DEFAULT 'light',
    glassmorphism BOOLEAN DEFAULT TRUE,
    animations BOOLEAN DEFAULT TRUE,
    
    -- Privacy
    show_online_status BOOLEAN DEFAULT TRUE,
    show_last_seen BOOLEAN DEFAULT TRUE,
    show_birthday BOOLEAN DEFAULT TRUE,
    allow_tagging BOOLEAN DEFAULT TRUE,
    allow_friend_requests BOOLEAN DEFAULT TRUE,
    
    -- Notifications
    email_notifications BOOLEAN DEFAULT TRUE,
    push_notifications BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_user_settings (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 13. Digital ID Cards
CREATE TABLE digital_ids (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    qr_code_data TEXT,
    card_data JSON,
    is_active BOOLEAN DEFAULT TRUE,
    shares_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_user_id_card (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 14. Analytics & Trends
CREATE TABLE analytics (
    id INT PRIMARY KEY AUTO_INCREMENT,
    date DATE NOT NULL,
    
    -- User Metrics
    new_users INT DEFAULT 0,
    active_users INT DEFAULT 0,
    total_users INT DEFAULT 0,
    
    -- Engagement
    total_posts INT DEFAULT 0,
    total_likes INT DEFAULT 0,
    total_comments INT DEFAULT 0,
    total_shares INT DEFAULT 0,
    
    -- Platform Health
    fake_accounts_detected INT DEFAULT 0,
    reports_resolved INT DEFAULT 0,
    avg_trust_score DECIMAL(5,2) DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_date (date)
);

-- Create Stored Procedures for Fake Account Detection
DELIMITER $$

CREATE PROCEDURE DetectFakeAccounts()
BEGIN
    -- Update trust scores based on various factors
    UPDATE users u
    LEFT JOIN (
        SELECT user_id,
               COUNT(*) as login_count,
               COUNT(DISTINCT ip_address) as unique_ips
        FROM login_logs
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY user_id
    ) ll ON u.id = ll.user_id
    SET u.trust_score = 
        CASE 
            WHEN u.avatar_url IS NULL THEN u.trust_score - 10
            WHEN u.post_count = 0 THEN u.trust_score - 15
            WHEN u.friend_count > 100 AND u.account_age_days < 7 THEN u.trust_score - 20
            WHEN ll.unique_ips > 3 THEN u.trust_score - 15
            WHEN u.profile_score < 30 THEN u.trust_score - 25
            ELSE u.trust_score + 5
        END,
        u.profile_score = 
            (CASE WHEN u.avatar_url IS NOT NULL THEN 20 ELSE 0 END) +
            (CASE WHEN u.bio IS NOT NULL THEN 15 ELSE 0 END) +
            (CASE WHEN u.location IS NOT NULL THEN 15 ELSE 0 END) +
            (CASE WHEN u.post_count > 5 THEN 25 ELSE u.post_count * 5 END) +
            (CASE WHEN u.friend_count BETWEEN 5 AND 100 THEN 25 ELSE 0 END);
    
    -- Flag suspicious accounts
    UPDATE users 
    SET active_status = 'suspended'
    WHERE trust_score < 20 
      AND account_age_days < 30
      AND active_status = 'active';
END$$

DELIMITER ;

-- Create Event to run fake account detection daily
CREATE EVENT IF NOT EXISTS daily_fake_account_check
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
    CALL DetectFakeAccounts();

-- Create Event to auto-delete expired stories
CREATE EVENT IF NOT EXISTS delete_expired_stories
ON SCHEDULE EVERY 1 HOUR
DO
    DELETE FROM stories WHERE expires_at < NOW();

-- Create Event to check birthdays
CREATE EVENT IF NOT EXISTS check_birthdays
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
BEGIN
    -- Create birthday notifications
    INSERT INTO notifications (user_id, type, title, message, related_id, related_type)
    SELECT 
        u.id as user_id,
        'birthday' as type,
        'Birthday Reminder' as title,
        CONCAT('Today is ', f.full_name, '''s birthday! Send them a wish.') as message,
        f.id as related_id,
        'user' as related_type
    FROM users u
    JOIN friendships fr ON u.id = fr.user_id AND fr.status = 'accepted'
    JOIN users f ON fr.friend_id = f.id
    JOIN birthdays b ON f.id = b.user_id
    WHERE DATE_FORMAT(b.birth_date, '%m-%d') = DATE_FORMAT(NOW(), '%m-%d')
      AND b.is_public = TRUE
      AND b.receive_wishes = TRUE;
END;

-- Insert default admin user
INSERT INTO admin_users (username, email, password_hash, role) 
VALUES ('admin', 'admin@friendsconnect.com', '$2b$10$YourHashedPasswordHere', 'super_admin');
