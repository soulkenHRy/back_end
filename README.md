# Quiz Game Leaderboard Backend

A Node.js + Express + MongoDB backend for the Quiz Game leaderboard system.

## Features

- User registration with device-based unique IDs
- Score submission and tracking
- Global leaderboard with rankings
- Score synchronization across devices
- RESTful API design

## API Endpoints

### Health Check
- `GET /` - API status
- `GET /health` - Health check for Railway

### Users
- `POST /api/users/register` - Register or update a user
- `GET /api/users/:userId` - Get user profile and rank
- `DELETE /api/users/:userId` - Delete a user

### Scores
- `POST /api/scores/submit` - Submit a score for a system
- `POST /api/scores/sync` - Sync all scores (bulk update)

### Leaderboard
- `GET /api/leaderboard` - Get global leaderboard (paginated)
- `GET /api/leaderboard/around/:userId` - Get users around a specific user

## Deployment to Railway

### Prerequisites
1. A GitHub account
2. A Railway account (https://railway.app)
3. A MongoDB Atlas account (for cloud database) or Railway's MongoDB plugin

### Steps

1. **Push to GitHub**
   ```bash
   cd backend
   git init
   git add .
   git commit -m "Initial backend setup"
   git remote add origin https://github.com/YOUR_USERNAME/quiz-game-backend.git
   git push -u origin main
   ```

2. **Create MongoDB Atlas Database**
   - Go to https://cloud.mongodb.com
   - Create a free cluster
   - Create a database user
   - Get your connection string

3. **Deploy to Railway**
   - Go to https://railway.app
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your repository
   - Add environment variable:
     - `MONGODB_URI`: Your MongoDB Atlas connection string
   - Railway will auto-detect Node.js and deploy

4. **Get Your Backend URL**
   - Railway will provide a public URL like: `https://quiz-game-backend-production.up.railway.app`
   - Use this URL in your Flutter app's `LeaderboardApiService`

## Local Development

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your MongoDB URI
   ```

3. **Start MongoDB locally** (if using local MongoDB)
   ```bash
   mongod
   ```

4. **Run the server**
   ```bash
   npm run dev  # Development with hot reload
   # or
   npm start    # Production
   ```

5. **Test the API**
   ```bash
   curl http://localhost:3000/
   ```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `MONGODB_URI` | MongoDB connection string | Yes |
| `PORT` | Server port (auto-set by Railway) | No (default: 3000) |

## Data Model

### User
```json
{
  "userId": "uuid-string",
  "username": "PlayerName",
  "country": "United States",
  "totalScore": 450,
  "systemsDesigned": 5,
  "averageScore": 90,
  "systemScores": [
    {
      "systemName": "URL Shortener (e.g., TinyURL)",
      "score": 95,
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ],
  "createdAt": "2024-01-01T00:00:00Z",
  "lastActive": "2024-01-15T10:30:00Z"
}
```

## License

MIT
