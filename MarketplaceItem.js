const mongoose = require('mongoose');

const marketplaceItemSchema = new mongoose.Schema({
  seller: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Description is required'],
    maxlength: [2000, 'Description cannot exceed 2000 characters']
  },
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative']
  },
  currency: {
    type: String,
    default: 'USD'
  },
  category: {
    type: String,
    required: [true, 'Category is required'],
    enum: [
      'electronics',
      'clothing',
      'furniture',
      'books',
      'vehicles',
      'real-estate',
      'services',
      'other'
    ]
  },
  condition: {
    type: String,
    enum: ['new', 'like-new', 'good', 'fair', 'poor'],
    default: 'good'
  },
  media_urls: [{
    type: String,
    required: true
  }],
  location: {
    type: String,
    required: [true, 'Location is required']
  },
  is_negotiable: {
    type: Boolean,
    default: false
  },
  is_sold: {
    type: Boolean,
    default: false
  },
  sold_to: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  sold_at: {
    type: Date
  },
  views: {
    type: Number,
    default: 0
  },
  saves: {
    type: Number,
    default: 0
  },
  is_deleted: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// Indexes for better search performance
marketplaceItemSchema.index({ title: 'text', description: 'text' });
marketplaceItemSchema.index({ category: 1, createdAt: -1 });
marketplaceItemSchema.index({ seller: 1 });
marketplaceItemSchema.index({ location: 1 });
marketplaceItemSchema.index({ price: 1 });
marketplaceItemSchema.index({ is_sold: 1, createdAt: -1 });

const MarketplaceItem = mongoose.model('MarketplaceItem', marketplaceItemSchema);
module.exports = MarketplaceItem;
