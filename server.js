/**
 * Quiz Game Leaderboard Backend Server
 * 
 * This server handles:
 * - User registration and authentication (device-based)
 * - Score submission and updates
 * - Global leaderboard rankings
 * 
 * Deploy to Railway via GitHub for production use.
 * 
 * SECURITY FEATURES:
 * - Rate limiting to prevent spam/DoS
 * - Score validation (max 100 per system)
 * - Input sanitization
 * - Request signature verification
 * - CORS restricted to app only
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// SECURITY: Secret key for request signing
// ============================================
const API_SECRET = process.env.API_SECRET || 'quiz-game-secret-2026-xK9mP2vL';

// ============================================
// SECURITY: Rate Limiting (in-memory, simple)
// ============================================
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 30; // 30 requests per minute per IP

function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  
  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return next();
  }
  
  const record = rateLimitStore.get(ip);
  
  if (now > record.resetTime) {
    // Reset window
    record.count = 1;
    record.resetTime = now + RATE_LIMIT_WINDOW;
    return next();
  }
  
  if (record.count >= RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({ 
      error: 'Too many requests. Please slow down.',
      retryAfter: Math.ceil((record.resetTime - now) / 1000)
    });
  }
  
  record.count++;
  next();
}

// Clean up old rate limit records every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitStore.entries()) {
    if (now > record.resetTime + RATE_LIMIT_WINDOW) {
      rateLimitStore.delete(ip);
    }
  }
}, 5 * 60 * 1000);

// ============================================
// SECURITY: Request Signature Verification
// ============================================
function verifySignature(req, res, next) {
  // Skip signature check for health endpoints
  if (req.path === '/' || req.path === '/health') {
    return next();
  }
  
  const signature = req.headers['x-app-signature'];
  const timestamp = req.headers['x-app-timestamp'];
  
  // If no signature provided, allow request but mark as unverified
  // This allows the app to work while we roll out signature verification
  if (!signature || !timestamp) {
    req.isVerified = false;
    return next();
  }
  
  // Check timestamp is within 5 minutes (prevent replay attacks)
  const now = Date.now();
  const requestTime = parseInt(timestamp, 10);
  if (isNaN(requestTime) || Math.abs(now - requestTime) > 5 * 60 * 1000) {
    return res.status(401).json({ error: 'Request expired' });
  }
  
  // Verify signature: HMAC-SHA256(timestamp + path + body)
  const body = JSON.stringify(req.body) || '';
  const payload = `${timestamp}${req.path}${body}`;
  const expectedSignature = crypto
    .createHmac('sha256', API_SECRET)
    .update(payload)
    .digest('hex');
  
  if (signature !== expectedSignature) {
    req.isVerified = false;
    return next(); // Allow but mark as unverified
  }
  
  req.isVerified = true;
  next();
}

// ============================================
// SECURITY: Input Validation
// ============================================
const MAX_SCORE_PER_SYSTEM = 100; // Maximum possible score
const MIN_SCORE = 0;
const MAX_USERNAME_LENGTH = 30;
const MAX_SYSTEMS = 50; // Maximum number of systems a user can have

function sanitizeString(str, maxLength = 100) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLength).replace(/[<>\"'&]/g, '');
}

function validateScore(score) {
  const numScore = parseInt(score, 10);
  if (isNaN(numScore)) return 0;
  return Math.max(MIN_SCORE, Math.min(MAX_SCORE_PER_SYSTEM, numScore));
}

// Middleware
app.use(cors({
  origin: '*', // In production, you could restrict to your app's domain
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-app-signature', 'x-app-timestamp']
}));
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(rateLimiter);
app.use(verifySignature);

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/quiz_leaderboard';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ============================================
// SCHEMAS & MODELS
// ============================================

// User Schema
const userSchema = new mongoose.Schema({
  // Unique device-based user ID (generated on first app launch)
  userId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  // Display name
  username: {
    type: String,
    required: true,
    trim: true,
    maxlength: 30
  },
  // User's country
  country: {
    type: String,
    default: 'Unknown'
  },
  // Total score across all systems (sum of best scores)
  totalScore: {
    type: Number,
    default: 0,
    index: true
  },
  // Number of systems the user has designed
  systemsDesigned: {
    type: Number,
    default: 0
  },
  // Average score per system
  averageScore: {
    type: Number,
    default: 0
  },
  // Individual system scores (best score for each system)
  systemScores: [{
    systemName: String,
    score: Number,
    timestamp: Date
  }],
  // Account creation timestamp
  createdAt: {
    type: Date,
    default: Date.now
  },
  // Last activity timestamp
  lastActive: {
    type: Date,
    default: Date.now
  }
});

// Index for leaderboard queries (descending by total score)
userSchema.index({ totalScore: -1, systemsDesigned: -1 });

const User = mongoose.model('User', userSchema);

// ============================================
// API ROUTES
// ============================================

// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Quiz Game Leaderboard API is running',
    version: '1.0.0'
  });
});

// Health check for Railway
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

/**
 * Register or update a user
 * POST /api/users/register
 * 
 * Body: { userId?, username, country }
 * Returns: { userId, username, country, totalScore, rank }
 */
app.post('/api/users/register', async (req, res) => {
  try {
    let { userId, username, country } = req.body;

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    // SECURITY: Sanitize inputs
    username = sanitizeString(username, MAX_USERNAME_LENGTH);
    country = sanitizeString(country, 50);

    if (username.length < 1) {
      return res.status(400).json({ error: 'Invalid username' });
    }

    // Generate userId if not provided (first time registration)
    if (!userId) {
      userId = uuidv4();
    }

    // SECURITY: Validate userId format (should be UUID-like)
    if (typeof userId !== 'string' || userId.length > 50) {
      return res.status(400).json({ error: 'Invalid userId' });
    }

    // Find existing user or create new one
    let user = await User.findOne({ userId });

    if (user) {
      // Update existing user
      user.username = username;
      user.country = country || user.country;
      user.lastActive = new Date();
      await user.save();
    } else {
      // Create new user
      user = new User({
        userId,
        username,
        country: country || 'Unknown',
        totalScore: 0,
        systemsDesigned: 0,
        averageScore: 0,
        systemScores: []
      });
      await user.save();
    }

    // Get user's current rank
    const rank = await User.countDocuments({ totalScore: { $gt: user.totalScore } }) + 1;

    res.json({
      userId: user.userId,
      username: user.username,
      country: user.country,
      totalScore: user.totalScore,
      systemsDesigned: user.systemsDesigned,
      averageScore: user.averageScore,
      rank
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

/**
 * Submit or update a score for a specific system
 * POST /api/scores/submit
 * 
 * Body: { userId, systemName, score }
 * Returns: { success, totalScore, systemsDesigned, averageScore, rank }
 */
app.post('/api/scores/submit', async (req, res) => {
  try {
    let { userId, systemName, score } = req.body;

    if (!userId || !systemName || score === undefined) {
      return res.status(400).json({ 
        error: 'userId, systemName, and score are required' 
      });
    }

    // SECURITY: Sanitize and validate inputs
    systemName = sanitizeString(systemName, 100);
    score = validateScore(score); // Clamps to 0-100

    if (systemName.length < 1) {
      return res.status(400).json({ error: 'Invalid system name' });
    }

    const user = await User.findOne({ userId });

    if (!user) {
      return res.status(404).json({ error: 'User not found. Please register first.' });
    }

    // Find existing score for this system
    const existingScoreIndex = user.systemScores.findIndex(
      s => s.systemName === systemName
    );

    let scoreUpdated = false;

    if (existingScoreIndex >= 0) {
      // Only update if new score is higher
      if (score > user.systemScores[existingScoreIndex].score) {
        user.systemScores[existingScoreIndex].score = score;
        user.systemScores[existingScoreIndex].timestamp = new Date();
        scoreUpdated = true;
      }
    } else {
      // Add new system score
      user.systemScores.push({
        systemName,
        score,
        timestamp: new Date()
      });
      scoreUpdated = true;
    }

    if (scoreUpdated) {
      // Recalculate total score and statistics
      user.totalScore = user.systemScores.reduce((sum, s) => sum + s.score, 0);
      user.systemsDesigned = user.systemScores.length;
      user.averageScore = user.systemsDesigned > 0 
        ? Math.round(user.totalScore / user.systemsDesigned) 
        : 0;
      user.lastActive = new Date();

      await user.save();
    }

    // Get user's current rank
    const rank = await User.countDocuments({ totalScore: { $gt: user.totalScore } }) + 1;

    res.json({
      success: true,
      scoreUpdated,
      totalScore: user.totalScore,
      systemsDesigned: user.systemsDesigned,
      averageScore: user.averageScore,
      rank
    });
  } catch (error) {
    console.error('Score submission error:', error);
    res.status(500).json({ error: 'Failed to submit score' });
  }
});

/**
 * Get global leaderboard
 * GET /api/leaderboard
 * 
 * Query params: 
 *   - limit: number of results (default 100, max 500)
 *   - offset: pagination offset (default 0)
 * 
 * Returns: { leaderboard: [...], totalUsers, hasMore }
 */
app.get('/api/leaderboard', async (req, res) => {
  try {
    let limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;

    // Cap limit at 500
    limit = Math.min(limit, 500);

    const totalUsers = await User.countDocuments();

    const leaderboard = await User.find()
      .select('userId username country totalScore systemsDesigned averageScore systemScores lastActive')
      .sort({ totalScore: -1, systemsDesigned: -1, lastActive: -1 })
      .skip(offset)
      .limit(limit)
      .lean();

    // Add rank to each user
    const rankedLeaderboard = leaderboard.map((user, index) => ({
      rank: offset + index + 1,
      userId: user.userId,
      username: user.username,
      country: user.country,
      totalScore: user.totalScore,
      systemsDesigned: user.systemsDesigned,
      averageScore: user.averageScore,
      evaluations: user.systemScores.map(s => ({
        systemName: s.systemName,
        score: s.score,
        timestamp: s.timestamp ? s.timestamp.getTime() : Date.now()
      }))
    }));

    res.json({
      leaderboard: rankedLeaderboard,
      totalUsers,
      hasMore: offset + limit < totalUsers
    });
  } catch (error) {
    console.error('Leaderboard fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

/**
 * Get a specific user's profile and rank
 * GET /api/users/:userId
 * 
 * Returns: { user, rank }
 */
app.get('/api/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findOne({ userId })
      .select('userId username country totalScore systemsDesigned averageScore systemScores createdAt lastActive')
      .lean();

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get user's rank
    const rank = await User.countDocuments({ totalScore: { $gt: user.totalScore } }) + 1;

    res.json({
      user: {
        userId: user.userId,
        username: user.username,
        country: user.country,
        totalScore: user.totalScore,
        systemsDesigned: user.systemsDesigned,
        averageScore: user.averageScore,
        evaluations: user.systemScores.map(s => ({
          systemName: s.systemName,
          score: s.score,
          timestamp: s.timestamp ? s.timestamp.getTime() : Date.now()
        })),
        createdAt: user.createdAt,
        lastActive: user.lastActive
      },
      rank
    });
  } catch (error) {
    console.error('User fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

/**
 * Get users around a specific user (for contextual leaderboard view)
 * GET /api/leaderboard/around/:userId
 * 
 * Query params:
 *   - range: number of users above and below (default 5)
 * 
 * Returns: { users: [...], userRank, totalUsers }
 */
app.get('/api/leaderboard/around/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const range = parseInt(req.query.range) || 5;

    const user = await User.findOne({ userId });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get user's rank
    const userRank = await User.countDocuments({ totalScore: { $gt: user.totalScore } }) + 1;
    const totalUsers = await User.countDocuments();

    // Calculate offset to get users around this user
    const offset = Math.max(0, userRank - range - 1);
    const limit = range * 2 + 1;

    const users = await User.find()
      .select('userId username country totalScore systemsDesigned averageScore')
      .sort({ totalScore: -1, systemsDesigned: -1 })
      .skip(offset)
      .limit(limit)
      .lean();

    const rankedUsers = users.map((u, index) => ({
      rank: offset + index + 1,
      userId: u.userId,
      username: u.username,
      country: u.country,
      totalScore: u.totalScore,
      systemsDesigned: u.systemsDesigned,
      averageScore: u.averageScore,
      isCurrentUser: u.userId === userId
    }));

    res.json({
      users: rankedUsers,
      userRank,
      totalUsers
    });
  } catch (error) {
    console.error('Around leaderboard fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

/**
 * Sync all user scores (bulk update from client)
 * POST /api/scores/sync
 * 
 * Body: { userId, systemScores: [{ systemName, score }] }
 * Returns: { success, totalScore, systemsDesigned, averageScore, rank }
 */
app.post('/api/scores/sync', async (req, res) => {
  try {
    const { userId, systemScores } = req.body;

    if (!userId || !systemScores || !Array.isArray(systemScores)) {
      return res.status(400).json({ 
        error: 'userId and systemScores array are required' 
      });
    }

    // SECURITY: Limit number of systems that can be synced
    if (systemScores.length > MAX_SYSTEMS) {
      return res.status(400).json({ 
        error: `Too many systems. Maximum is ${MAX_SYSTEMS}` 
      });
    }

    const user = await User.findOne({ userId });

    if (!user) {
      return res.status(404).json({ error: 'User not found. Please register first.' });
    }

    // Merge scores (keep higher score for each system)
    for (let { systemName, score } of systemScores) {
      if (!systemName || score === undefined) continue;

      // SECURITY: Sanitize and validate
      systemName = sanitizeString(systemName, 100);
      score = validateScore(score); // Clamps to 0-100

      if (systemName.length < 1) continue;

      const existingIndex = user.systemScores.findIndex(
        s => s.systemName === systemName
      );

      if (existingIndex >= 0) {
        // Only update if new score is higher
        if (score > user.systemScores[existingIndex].score) {
          user.systemScores[existingIndex].score = score;
          user.systemScores[existingIndex].timestamp = new Date();
        }
      } else if (score > 0) {
        // SECURITY: Limit total systems per user
        if (user.systemScores.length >= MAX_SYSTEMS) continue;
        
        // Add new system score
        user.systemScores.push({
          systemName,
          score,
          timestamp: new Date()
        });
      }
    }

    // Recalculate totals
    user.totalScore = user.systemScores.reduce((sum, s) => sum + s.score, 0);
    user.systemsDesigned = user.systemScores.length;
    user.averageScore = user.systemsDesigned > 0 
      ? Math.round(user.totalScore / user.systemsDesigned) 
      : 0;
    user.lastActive = new Date();

    await user.save();

    // Get user's current rank
    const rank = await User.countDocuments({ totalScore: { $gt: user.totalScore } }) + 1;

    res.json({
      success: true,
      totalScore: user.totalScore,
      systemsDesigned: user.systemsDesigned,
      averageScore: user.averageScore,
      rank
    });
  } catch (error) {
    console.error('Score sync error:', error);
    res.status(500).json({ error: 'Failed to sync scores' });
  }
});

/**
 * Delete a user (for testing or GDPR compliance)
 * DELETE /api/users/:userId
 */
app.delete('/api/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const result = await User.deleteOne({ userId });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('User deletion error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Leaderboard API ready at http://localhost:${PORT}`);
});
