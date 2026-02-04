class FriendsConnect {
    constructor() {
        this.baseUrl = 'http://localhost:5000/api';
        this.token = localStorage.getItem('token');
        this.user = JSON.parse(localStorage.getItem('user') || 'null');
        this.socket = null;
        this.onlineUsers = new Map();
        this.typingTimeouts = new Map();
        
        this.initializeSocket();
        this.setupEventListeners();
        this.checkAuth();
    }
  
        if (!this.token) return;
        
        this.socket = io('http://localhost:5000', {
            auth: { token: this.token }
        });
        
        this.socket.on('connect', () => {
            console.log('Socket connected');
        });
        
        this.socket.on('authenticated', () => {
            console.log('Socket authenticated');
        });
        
        this.socket.on('user_online', (data) => {
            this.onlineUsers.set(data.userId, true);
            this.updateOnlineStatus(data.userId, true);
        });
        
        this.socket.on('user_offline', (data) => {
            this.onlineUsers.set(data.userId, false);
            this.updateOnlineStatus(data.userId, false);
        });
        
        this.socket.on('new_message', (message) => {
            this.handleNewMessage(message);
        });
        
        this.socket.on('message_deleted', (data) => {
            this.handleMessageDeleted(data.messageId);
        });
        
        this.socket.on('user_typing', (data) => {
            this.showTypingIndicator(data.userId, data.conversationId, data.isTyping);
        });
        
        this.socket.on('messages_read', (data) => {
            this.markMessagesAsRead(data.conversationId, data.userId);
        });
        
        this.socket.on('new_notification', (notification) => {
            this.showNotification(notification);
        });
        
        this.socket.on('friend_request_accepted', (data) => {
            this.showToast(`${data.userName} accepted your friend request`, 'success');
        });
        
        this.socket.on('post_reacted', (data) => {
            this.updatePostReaction(data.postId, data.userId, data.reactionType);
        });
        
        this.socket.on('new_comment', (data) => {
            this.addNewComment(data.postId, data.commentId, data.userName);
        });
        
        this.socket.on('post_shared', (data) => {
            this.showToast(`${data.userName} shared your post`, 'info');
        });
        
        this.socket.on('birthday_wish', (data) => {
            this.showBirthdayAnimation(data.giftType, data.userName);
        });
    }
    
    async checkAuth() {
        if (this.token && this.user) {
            try {
                const response = await fetch(`${this.baseUrl}/users/me`, {
                    headers: { 'Authorization': `Bearer ${this.token}` }
                });
                
                if (!response.ok) {
                    this.logout();
                } else {
                    this.user = await response.json();
                    localStorage.setItem('user', JSON.stringify(this.user));
                    this.updateUI();
                }
            } catch (error) {
                this.logout();
            }
        } else {
            this.showAuthPage();
        }
    }
    
    async login(email, password) {
        try {
            const response = await fetch(`${this.baseUrl}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    email, 
                    password,
                    device_info: navigator.userAgent,
                    ip_address: await this.getIPAddress()
                })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Login failed');
            }
            
            this.token = data.token;
            this.user = data.user;
            
            localStorage.setItem('token', this.token);
            localStorage.setItem('user', JSON.stringify(this.user));
            
            this.initializeSocket();
            this.updateUI();
            this.showToast('Login successful', 'success');
            
            return true;
        } catch (error) {
            this.showToast(error.message, 'error');
            return false;
        }
    }
    
    async register(userData) {
        try {
            const response = await fetch(`${this.baseUrl}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Registration failed');
            }
            
            this.token = data.token;
            this.user = { id: data.userId };
            
            localStorage.setItem('token', this.token);
            
            this.showToast('Registration successful. Please verify your email.', 'success');
            return true;
        } catch (error) {
            this.showToast(error.message, 'error');
            return false;
        }
    }
    
    logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        this.token = null;
        this.user = null;
        
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
        
        this.showAuthPage();
    }
    
    async createPost(postData, files = []) {
        try {
            const formData = new FormData();
            
            // Add post data
            Object.keys(postData).forEach(key => {
                if (postData[key] !== undefined) {
                    if (key === 'tagged_users' && Array.isArray(postData[key])) {
                        formData.append(key, JSON.stringify(postData[key]));
                    } else {
                        formData.append(key, postData[key]);
                    }
                }
            });
            
            // Add files
            files.forEach(file => {
                formData.append('post_media', file);
            });
            
            const response = await fetch(`${this.baseUrl}/posts`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${this.token}` },
                body: formData
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to create post');
            }
            
            this.showToast('Post created successfully', 'success');
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async getFeed(page = 1) {
        try {
            const response = await fetch(`${this.baseUrl}/posts/feed?page=${page}&limit=20`, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to load feed');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            return [];
        }
    }
    
    async reactToPost(postId, reactionType) {
        try {
            const response = await fetch(`${this.baseUrl}/posts/${postId}/react`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ reaction_type: reactionType })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to react to post');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async addComment(postId, content, parentId = null) {
        try {
            const response = await fetch(`${this.baseUrl}/posts/${postId}/comment`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content, parent_id: parentId })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to add comment');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async sendFriendRequest(userId) {
        try {
            const response = await fetch(`${this.baseUrl}/friends/request`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ receiver_id: userId })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to send friend request');
            }
            
            this.showToast('Friend request sent', 'success');
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async respondToFriendRequest(requestId, action) {
        try {
            const response = await fetch(`${this.baseUrl}/friends/request/${requestId}/respond`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to respond to friend request');
            }
            
            this.showToast(`Friend request ${action}ed`, 'success');
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async sendMessage(conversationId, content, file = null) {
        try {
            const formData = new FormData();
            formData.append('content', content);
            
            if (file) {
                formData.append('message_media', file);
            }
            
            const response = await fetch(`${this.baseUrl}/conversations/${conversationId}/messages`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${this.token}` },
                body: formData
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to send message');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async getConversations() {
        try {
            const response = await fetch(`${this.baseUrl}/conversations`, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to load conversations');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            return [];
        }
    }
    
    async getMessages(conversationId, before = null) {
        try {
            let url = `${this.baseUrl}/conversations/${conversationId}/messages?limit=50`;
            if (before) url += `&before=${before}`;
            
            const response = await fetch(url, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to load messages');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            return [];
        }
    }
    
    async joinConversation(conversationId) {
        if (this.socket) {
            this.socket.emit('join_conversation', conversationId);
        }
    }
    
    async leaveConversation(conversationId) {
        if (this.socket) {
            this.socket.emit('leave_conversation', conversationId);
        }
    }
    
    async sendTypingIndicator(conversationId, isTyping) {
        if (this.socket) {
            this.socket.emit('typing', { conversationId, isTyping });
        }
    }
    
    async markMessageAsRead(messageId, conversationId) {
        if (this.socket) {
            this.socket.emit('message_read', { messageId, conversationId });
        }
    }
    
    async createGroup(groupData) {
        try {
            const formData = new FormData();
            
            Object.keys(groupData).forEach(key => {
                if (groupData[key] !== undefined) {
                    formData.append(key, groupData[key]);
                }
            });
            
            const response = await fetch(`${this.baseUrl}/groups`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${this.token}` },
                body: formData
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to create group');
            }
            
            this.showToast('Group created successfully', 'success');
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async getNotifications(unreadOnly = false) {
        try {
            let url = `${this.baseUrl}/notifications`;
            if (unreadOnly) url += '?unread=true';
            
            const response = await fetch(url, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to load notifications');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            return [];
        }
    }
    
    async markNotificationAsRead(notificationId) {
        try {
            const response = await fetch(`${this.baseUrl}/notifications/${notificationId}/read`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to mark notification as read');
            }
            
            return data;
        } catch (error) {
            throw error;
        }
    }
    
    async getUpcomingBirthdays() {
        try {
            const response = await fetch(`${this.baseUrl}/birthdays/upcoming`, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to load birthdays');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            return [];
        }
    }
    
    async sendBirthdayWish(userId, message, giftType = 'cake') {
        try {
            const response = await fetch(`${this.baseUrl}/birthdays/${userId}/wish`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message, gift_type: giftType })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to send birthday wish');
            }
            
            this.showToast('Birthday wish sent', 'success');
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async generateQRCode() {
        try {
            const response = await fetch(`${this.baseUrl}/users/me/qrcode`, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to generate QR code');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async reportUser(userId, reportType, description, evidence = null) {
        try {
            const response = await fetch(`${this.baseUrl}/reports/user`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    reported_user_id: userId, 
                    report_type: reportType,
                    description,
                    evidence
                })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to report user');
            }
            
            this.showToast('User reported successfully', 'success');
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async getTrendingPosts() {
        try {
            const response = await fetch(`${this.baseUrl}/posts/trending`, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to load trending posts');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            return [];
        }
    }
    
    async createStory(mediaFile, textContent = '', bgColor = '#000000', fontStyle = 'Arial') {
        try {
            const formData = new FormData();
            formData.append('story_media', mediaFile);
            formData.append('text_content', textContent);
            formData.append('bg_color', bgColor);
            formData.append('font_style', fontStyle);
            
            const response = await fetch(`${this.baseUrl}/stories`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${this.token}` },
                body: formData
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to create story');
            }
            
            this.showToast('Story created successfully', 'success');
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }
    
    async getStories() {
        try {
            const response = await fetch(`${this.baseUrl}/stories/feed`, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to load stories');
            }
            
            return data;
        } catch (error) {
            this.showToast(error.message, 'error');
            return [];
        }
    }
    
    async viewStory(storyId) {
        try {
            const response = await fetch(`${this.baseUrl}/stories/${storyId}/view`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to view story');
            }
            
            return data;
        } catch (error) {
            throw error;
        }
    }
    
    // Utility methods
    async getIPAddress() {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch (error) {
            return 'unknown';
        }
    }
    
    showToast(message, type = 'info') {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.classList.add('show');
        }, 10);
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 300);
        }, 3000);
    }
    
    showNotification(notification) {
        // Show browser notification if permitted
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification('FriendsConnect', {
                body: notification.content,
                icon: this.user?.profile_pic || '/default-avatar.png'
            });
        }
        
        // Show in-app notification
        this.showToast(notification.content, 'info');
        
        // Update notification count
        this.updateNotificationCount();
    }
    
    updateNotificationCount() {
        // Update notification badge in UI
        const badge = document.querySelector('.notification-badge');
        if (badge) {
            this.getNotifications(true).then(notifications => {
                const unreadCount = notifications.length;
                badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
                badge.style.display = unreadCount > 0 ? 'flex' : 'none';
            });
        }
    }
    
    updateOnlineStatus(userId, isOnline) {
        // Update online status indicator in UI
        const indicator = document.querySelector(`[data-user-id="${userId}"] .online-status`);
        if (indicator) {
            indicator.className = `online-status ${isOnline ? 'online' : 'offline'}`;
            indicator.title = isOnline ? 'Online now' : 'Offline';
        }
    }
    
    showTypingIndicator(userId, conversationId, isTyping) {
        const typingIndicator = document.querySelector(`[data-conversation-id="${conversationId}"] .typing-indicator`);
        
        if (typingIndicator) {
            if (isTyping) {
                typingIndicator.textContent = 'Typing...';
                typingIndicator.style.display = 'block';
                
                // Clear previous timeout
                if (this.typingTimeouts.has(conversationId)) {
                    clearTimeout(this.typingTimeouts.get(conversationId));
                }
                
                // Set timeout to hide typing indicator
                const timeout = setTimeout(() => {
                    typingIndicator.style.display = 'none';
                }, 3000);
                
                this.typingTimeouts.set(conversationId, timeout);
            } else {
                typingIndicator.style.display = 'none';
            }
        }
    }
    
    handleNewMessage(message) {
        // Add message to UI
        const conversation = document.querySelector(`[data-conversation-id="${message.conversation_id}"]`);
        if (conversation) {
            this.addMessageToUI(message);
            
            // Scroll to bottom
            const messagesContainer = conversation.querySelector('.messages-container');
            if (messagesContainer) {
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            }
        }
        
        // Update conversation list
        this.updateConversationList(message.conversation_id, message);
    }
    
    handleMessageDeleted(messageId) {
        // Remove message from UI
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (messageElement) {
            messageElement.innerHTML = '<em>This message was deleted</em>';
            messageElement.classList.add('deleted');
        }
    }
    
    markMessagesAsRead(conversationId, userId) {
        // Mark messages as read in UI
        const messages = document.querySelectorAll(`[data-conversation-id="${conversationId}"] .message[data-sender-id="${userId}"]`);
        messages.forEach(msg => {
            msg.classList.add('read');
        });
    }
    
    updatePostReaction(postId, userId, reactionType) {
        // Update reaction count in UI
        const reactionElement = document.querySelector(`[data-post-id="${postId}"] .reactions-count`);
        if (reactionElement) {
            // Update count and show animation
            reactionElement.textContent = parseInt(reactionElement.textContent || 0) + 1;
            reactionElement.classList.add('pulse');
            setTimeout(() => reactionElement.classList.remove('pulse'), 300);
        }
    }
    
    addNewComment(postId, commentId, userName) {
        // Add new comment to UI
        const commentsContainer = document.querySelector(`[data-post-id="${postId}"] .comments-container`);
        if (commentsContainer) {
            // Show notification and update count
            this.showToast(`${userName} commented on your post`, 'info');
            
            const countElement = commentsContainer.querySelector('.comments-count');
            if (countElement) {
                const currentCount = parseInt(countElement.textContent || 0);
                countElement.textContent = currentCount + 1;
            }
        }
    }
    
    showBirthdayAnimation(giftType, userName) {
        // Show birthday animation
        const animation = document.createElement('div');
        animation.className = `birthday-animation ${giftType}`;
        animation.innerHTML = `
            <div class="confetti"></div>
            <div class="gift">🎁</div>
            <p>${userName} sent you a birthday ${giftType}!</p>
        `;
        
        document.body.appendChild(animation);
        
        setTimeout(() => {
            animation.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            animation.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(animation);
            }, 500);
        }, 3000);
    }
    
    updateUI() {
        // Update UI based on user authentication
        const authElements = document.querySelectorAll('.auth-only');
        const guestElements = document.querySelectorAll('.guest-only');
        
        if (this.user) {
            authElements.forEach(el => el.style.display = '');
            guestElements.forEach(el => el.style.display = 'none');
            
            // Update user info
            const userElements = document.querySelectorAll('[data-user-info]');
            userElements.forEach(el => {
                const infoType = el.getAttribute('data-user-info');
                if (infoType === 'name') el.textContent = this.user.full_name;
                if (infoType === 'username') el.textContent = `@${this.user.username}`;
                if (infoType === 'avatar') el.src = this.user.profile_pic || '/default-avatar.png';
            });
            
            // Load initial data
            this.loadInitialData();
        } else {
            authElements.forEach(el => el.style.display = 'none');
            guestElements.forEach(el => el.style.display = '');
        }
    }
    
    async loadInitialData() {
        // Load initial data after login
        await Promise.all([
            this.getFeed(),
            this.getNotifications(),
            this.getConversations(),
            this.getUpcomingBirthdays()
        ]);
        
        // Update notification count
        this.updateNotificationCount();
    }
    
    setupEventListeners() {
        // Setup global event listeners
        document.addEventListener('click', (e) => {
            // Handle like button
            if (e.target.closest('.like-btn')) {
                e.preventDefault();
                const postId = e.target.closest('[data-post-id]').getAttribute('data-post-id');
                this.reactToPost(postId, 'like');
            }
            
            // Handle comment button
            if (e.target.closest('.comment-btn')) {
                e.preventDefault();
                const postId = e.target.closest('[data-post-id]').getAttribute('data-post-id');
                const commentInput = document.querySelector(`[data-post-id="${postId}"] .comment-input`);
                commentInput?.focus();
            }
            
            // Handle friend request accept
            if (e.target.closest('.accept-friend-btn')) {
                e.preventDefault();
                const requestId = e.target.closest('[data-request-id]').getAttribute('data-request-id');
                this.respondToFriendRequest(requestId, 'accept');
            }
            
            // Handle friend request reject
            if (e.target.closest('.reject-friend-btn')) {
                e.preventDefault();
                const requestId = e.target.closest('[data-request-id]').getAttribute('data-request-id');
                this.respondToFriendRequest(requestId, 'reject');
            }
        });
        
        // Handle message input typing
        document.addEventListener('input', (e) => {
            if (e.target.classList.contains('message-input')) {
                const conversationId = e.target.getAttribute('data-conversation-id');
                if (conversationId) {
                    this.sendTypingIndicator(conversationId, true);
                    
                    // Clear typing after delay
                    setTimeout(() => {
                        this.sendTypingIndicator(conversationId, false);
                    }, 1000);
                }
            }
        });
    }
    
    showAuthPage() {
        // Show authentication page
        document.body.innerHTML = `
            <div class="auth-container">
                <div class="auth-box">
                    <h1>FriendsConnect</h1>
                    <div class="auth-tabs">
                        <button class="tab-btn active" data-tab="login">Login</button>
                        <button class="tab-btn" data-tab="register">Register</button>
                    </div>
                    <form id="login-form" class="auth-form active">
                        <input type="email" placeholder="Email" required>
                        <input type="password" placeholder="Password" required>
                        <button type="submit">Login</button>
                        <a href="#" class="forgot-password">Forgot password?</a>
                    </form>
                    <form id="register-form" class="auth-form">
                        <input type="text" placeholder="Full Name" required>
                        <input type="text" placeholder="Username" required>
                        <input type="email" placeholder="Email" required>
                        <input type="password" placeholder="Password" required>
                        <input type="date" placeholder="Birthdate">
                        <button type="submit">Register</button>
                    </form>
                </div>
            </div>
        `;
        
        // Add auth form handlers
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = e.target.querySelector('input[type="email"]').value;
            const password = e.target.querySelector('input[type="password"]').value;
            await this.login(email, password);
        });
        
        document.getElementById('register-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = {
                full_name: e.target.querySelector('input[placeholder="Full Name"]').value,
                username: e.target.querySelector('input[placeholder="Username"]').value,
                email: e.target.querySelector('input[type="email"]').value,
                password: e.target.querySelector('input[type="password"]').value,
                birthdate: e.target.querySelector('input[type="date"]').value
            };
            await this.register(formData);
        });
        
        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-btn, .auth-form').forEach(el => el.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(`${btn.dataset.tab}-form`).classList.add('active');
            });
        });
    }
}

// Initialize the application
const app = new FriendsConnect();

// CSS Styles (add to your stylesheet)
const styles = `
/* Toast notifications */
.toast {
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 24px;
    border-radius: 8px;
    color: white;
    font-weight: 500;
    transform: translateX(100%);
    opacity: 0;
    transition: all 0.3s ease;
    z-index: 9999;
}

.toast.show {
    transform: translateX(0);
    opacity: 1;
}

.toast-success { background: linear-gradient(135deg, #10b981, #34d399); }
.toast-error { background: linear-gradient(135deg, #f43f5e, #fb7185); }
.toast-info { background: linear-gradient(135deg, #3b82f6, #60a5fa); }
.toast-warning { background: linear-gradient(135deg, #f59e0b, #fbbf24); }

/* Online status indicators */
.online-status {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    border: 2px solid white;
    position: absolute;
    bottom: 0;
    right: 0;
}

.online-status.online { background: #10b981; }
.online-status.offline { background: #9ca3af; }

/* Typing indicator */
.typing-indicator {
    font-size: 12px;
    color: #6b7280;
    font-style: italic;
    display: none;
}

/* Birthday animation */
.birthday-animation {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    z-index: 99999;
    opacity: 0;
    transition: opacity 0.5s ease;
}

.birthday-animation.show {
    opacity: 1;
}

.birthday-animation .confetti {
    position: absolute;
    width: 100%;
    height: 100%;
    background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path fill="%23f43f5e" d="M50,10 L60,40 L90,50 L60,60 L50,90 L40,60 L10,50 L40,40 Z"/></svg>') repeat;
    animation: confetti-fall 3s linear infinite;
}

.birthday-animation .gift {
    font-size: 100px;
    animation: bounce 1s infinite;
}

.birthday-animation p {
    color: white;
    font-size: 24px;
    margin-top: 20px;
    text-align: center;
}

@keyframes confetti-fall {
    0% { transform: translateY(-100vh); }
    100% { transform: translateY(100vh); }
}

@keyframes bounce {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-20px); }
}

/* Pulse animation for reactions */
.pulse {
    animation: pulse 0.3s ease;
}

@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.2); }
    100% { transform: scale(1); }
}

/* Authentication styles */
.auth-container {
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    background: linear-gradient(135deg, #0f172a, #1e293b);
}

.auth-box {
    background: rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
    border-radius: 16px;
    padding: 40px;
    width: 100%;
    max-width: 400px;
    border: 1px solid rgba(255, 255, 255, 0.2);
}

.auth-tabs {
    display: flex;
    margin-bottom: 30px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.2);
}

.tab-btn {
    flex: 1;
    padding: 12px;
    background: none;
    border: none;
    color: #cbd5e1;
    font-size: 16px;
    cursor: pointer;
    transition: all 0.3s ease;
}

.tab-btn.active {
    color: #6366f1;
    border-bottom: 2px solid #6366f1;
}

.auth-form {
    display: none;
}

.auth-form.active {
    display: block;
}

.auth-form input {
    width: 100%;
    padding: 12px 16px;
    margin-bottom: 16px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    color: white;
    font-size: 14px;
}

.auth-form input::placeholder {
    color: #94a3b8;
}

.auth-form button {
    width: 100%;
    padding: 12px;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    border: none;
    border-radius: 8px;
    color: white;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.3s ease;
}

.auth-form button:hover {
    transform: translateY(-2px);
}

.forgot-password {
    display: block;
    text-align: center;
    margin-top: 16px;
    color: #94a3b8;
    text-decoration: none;
    font-size: 14px;
}

.forgot-password:hover {
    color: #6366f1;
}

/* Main app styles */
.main-container {
    display: grid;
    grid-template-columns: 280px 1fr 320px;
    min-height: 100vh;
    background: linear-gradient(135deg, #0f172a, #1e293b);
    color: #f1f5f9;
}

.sidebar {
    padding: 20px;
    border-right: 1px solid rgba(255, 255, 255, 0.1);
}

.main-content {
    padding: 20px;
}

.right-sidebar {
    padding: 20px;
    border-left: 1px solid rgba(255, 255, 255, 0.1);
}

/* Post styles */
.post {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.post-header {
    display: flex;
    align-items: center;
    margin-bottom: 16px;
}

.post-avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    margin-right: 12px;
    position: relative;
}

.post-content {
    margin-bottom: 16px;
    line-height: 1.6;
}

.post-media {
    margin-top: 16px;
    border-radius: 8px;
    overflow: hidden;
}

.post-media img, .post-media video {
    width: 100%;
    max-height: 500px;
    object-fit: cover;
}

.post-actions {
    display: flex;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
    padding-top: 12px;
}

.post-action-btn {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 8px;
    background: none;
    border: none;
    color: #cbd5e1;
    cursor: pointer;
    border-radius: 6px;
    transition: all 0.3s ease;
}

.post-action-btn:hover {
    background: rgba(255, 255, 255, 0.1);
}

/* Chat styles */
.chat-container {
    display: flex;
    flex-direction: column;
    height: 100%;
}

.messages-container {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
}

.message {
    margin-bottom: 12px;
    max-width: 70%;
}

.message.sent {
    margin-left: auto;
}

.message-content {
    padding: 12px 16px;
    border-radius: 18px;
    background: rgba(255, 255, 255, 0.1);
}

.message.sent .message-content {
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
}

.message-input-container {
    padding: 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
}

.message-input {
    width: 100%;
    padding: 12px 16px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(255, 255, 255, 0.1);
    border-radius: 24px;
    color: white;
    font-size: 14px;
}

/* Notification badge */
.notification-badge {
    background: linear-gradient(135deg, #f43f5e, #fb7185);
    color: white;
    font-size: 12px;
    font-weight: 600;
    min-width: 20px;
    height: 20px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: absolute;
    top: -5px;
    right: -5px;
}

/* Theme variables */
:root {
    --primary: #6366f1;
    --primary-dark: #4f46e5;
    --primary-light: #818cf8;
    --secondary: #10b981;
    --accent: #f43f5e;
    --dark: #0f172a;
    --darker: #020617;
    --light: #f8fafc;
    --gray-50: #f8fafc;
    --gray-100: #f1f5f9;
    --gray-200: #e2e8f0;
    --gray-300: #cbd5e1;
    --gray-400: #94a3b8;
    --gray-500: #64748b;
    --gray-600: #475569;
    --gray-700: #334155;
    --gray-800: #1e293b;
    --gray-900: #0f172a;
}

/* Responsive design */
@media (max-width: 1200px) {
    .main-container {
        grid-template-columns: 240px 1fr;
    }
    
    .right-sidebar {
        display: none;
    }
}

@media (max-width: 768px) {
    .main-container {
        grid-template-columns: 1fr;
    }
    
    .sidebar {
        display: none;
    }
}

/* Glassmorphism effects */
.glass {
    background: rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
}

/* Smooth transitions */
* {
    transition: background-color 0.3s ease, border-color 0.3s ease;
}
`;

// Add styles to document
const styleSheet = document.createElement('style');
styleSheet.textContent = styles;
document.head.appendChild(styleSheet);
