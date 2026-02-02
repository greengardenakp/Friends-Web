const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directory exists
const uploadDir = 'public/uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let folder = 'uploads';
    
    if (file.fieldname === 'avatar') {
      folder = 'uploads/avatars';
    } else if (file.fieldname === 'post_media') {
      folder = 'uploads/posts';
    } else if (file.fieldname === 'story_media') {
      folder = 'uploads/stories';
    } else if (file.fieldname === 'marketplace_media') {
      folder = 'uploads/marketplace';
    }
    
    const fullPath = `public/${folder}`;
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
    }
    
    cb(null, fullPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|mp4|mov|avi|mkv|webm/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    cb(null, true);
  } else {
    cb(new Error('Only image and video files are allowed'));
  }
};

// Create upload instance
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB limit
  },
  fileFilter: fileFilter
});

// Specific upload handlers
const uploadAvatar = upload.single('avatar');
const uploadPostMedia = upload.array('post_media', 10);
const uploadStoryMedia = upload.single('story_media');
const uploadMarketplaceMedia = upload.array('marketplace_media', 10);

module.exports = {
  uploadAvatar,
  uploadPostMedia,
  uploadStoryMedia,
  uploadMarketplaceMedia,
  upload
};
