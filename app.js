const express = require('express')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const app = express()

app.use(express.json())

const dbPromise = open({
  filename: './twitterClone.db',
  driver: sqlite3.Database,
})

const jwtSecret = 'your_jwt_secret'

// Middleware to authenticate the JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.status(401).json({error: 'Invalid JWT Token'})

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.status(401).json({error: 'Invalid JWT Token'})
    req.user = user
    next()
  })
}

// Register API
app.post('/register/', async (req, res) => {
  const {username, password, name, gender} = req.body
  if (password.length < 6) {
    return res.status(400).json({error: 'Password is too short'})
  }

  const db = await dbPromise
  const userExists = await db.get(
    'SELECT * FROM user WHERE username = ?',
    username,
  )

  if (userExists) {
    return res.status(400).json({error: 'User already exists'})
  }

  const hashedPassword = await bcrypt.hash(password, 10)
  await db.run(
    'INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)',
    [name, username, hashedPassword, gender],
  )

  res.status(200).json({message: 'User created successfully'})
})

// Login API
app.post('/login/', async (req, res) => {
  const {username, password} = req.body
  const db = await dbPromise
  const user = await db.get('SELECT * FROM user WHERE username = ?', username)

  if (!user) {
    return res.status(400).json({error: 'Invalid user'})
  }

  const validPassword = await bcrypt.compare(password, user.password)
  if (!validPassword) {
    return res.status(400).json({error: 'Invalid password'})
  }

  const token = jwt.sign({user_id: user.user_id}, jwtSecret, {expiresIn: '1h'})
  res.json({jwtToken: token})
})

// API 3: Get latest tweets of people whom the user follows (4 tweets at a time)
app.get('/user/tweets/feed/', authenticateToken, async (req, res) => {
  const {user_id} = req.user
  const db = await dbPromise

  const tweets = await db.all(
    `
    SELECT user.username, tweet.tweet, tweet.date_time as dateTime 
    FROM tweet
    JOIN follower ON tweet.user_id = follower.following_user_id
    JOIN user ON user.user_id = tweet.user_id
    WHERE follower.follower_user_id = ?
    ORDER BY tweet.date_time DESC
    LIMIT 4
  `,
    [user_id],
  )

  res.json(tweets)
})

// API 4: Get list of people whom the user follows
app.get('/user/following/', authenticateToken, async (req, res) => {
  const {user_id} = req.user
  const db = await dbPromise

  const following = await db.all(
    `
    SELECT user.name 
    FROM user
    JOIN follower ON user.user_id = follower.following_user_id
    WHERE follower.follower_user_id = ?
  `,
    [user_id],
  )

  res.json(following)
})

// API 5: Get list of people who follow the user
app.get('/user/followers/', authenticateToken, async (req, res) => {
  const {user_id} = req.user
  const db = await dbPromise

  const followers = await db.all(
    `
    SELECT user.name 
    FROM user
    JOIN follower ON user.user_id = follower.follower_user_id
    WHERE follower.following_user_id = ?
  `,
    [user_id],
  )

  res.json(followers)
})

// API 6: Get a tweet by ID with like and reply counts if the user follows the tweet's author
app.get('/tweets/:tweetId/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params
  const {user_id} = req.user
  const db = await dbPromise

  const tweet = await db.get(
    `
    SELECT tweet.*, 
           (SELECT COUNT(*) FROM like WHERE tweet_id = tweet.tweet_id) as likes,
           (SELECT COUNT(*) FROM reply WHERE tweet_id = tweet.tweet_id) as replies
    FROM tweet
    JOIN follower ON tweet.user_id = follower.following_user_id
    WHERE follower.follower_user_id = ? AND tweet.tweet_id = ?
  `,
    [user_id, tweetId],
  )

  if (!tweet) {
    return res.status(401).json({error: 'Invalid Request'})
  }

  res.json({
    tweet: tweet.tweet,
    likes: tweet.likes,
    replies: tweet.replies,
    dateTime: tweet.date_time,
  })
})

// API 7: Get likes for a tweet by ID if the user follows the tweet's author
app.get('/tweets/:tweetId/likes/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params
  const {user_id} = req.user
  const db = await dbPromise

  const followsTweet = await db.get(
    `
    SELECT 1 FROM tweet
    JOIN follower ON tweet.user_id = follower.following_user_id
    WHERE follower.follower_user_id = ? AND tweet.tweet_id = ?
  `,
    [user_id, tweetId],
  )

  if (!followsTweet) {
    return res.status(401).json({error: 'Invalid Request'})
  }

  const likes = await db.all(
    `
    SELECT user.username 
    FROM like
    JOIN user ON like.user_id = user.user_id
    WHERE like.tweet_id = ?
  `,
    [tweetId],
  )

  res.json({likes: likes.map(like => like.username)})
})

// API 8: Get replies for a tweet by ID if the user follows the tweet's author
app.get('/tweets/:tweetId/replies/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params
  const {user_id} = req.user
  const db = await dbPromise

  const followsTweet = await db.get(
    `
    SELECT 1 FROM tweet
    JOIN follower ON tweet.user_id = follower.following_user_id
    WHERE follower.follower_user_id = ? AND tweet.tweet_id = ?
  `,
    [user_id, tweetId],
  )

  if (!followsTweet) {
    return res.status(401).json({error: 'Invalid Request'})
  }

  const replies = await db.all(
    `
    SELECT user.name, reply.reply
    FROM reply
    JOIN user ON reply.user_id = user.user_id
    WHERE reply.tweet_id = ?
  `,
    [tweetId],
  )

  res.json({replies})
})

// API 9: Get all tweets of the user
app.get('/user/tweets/', authenticateToken, async (req, res) => {
  const {user_id} = req.user
  const db = await dbPromise

  const tweets = await db.all(
    `
    SELECT tweet.tweet, 
           (SELECT COUNT(*) FROM like WHERE tweet_id = tweet.tweet_id) as likes,
           (SELECT COUNT(*) FROM reply WHERE tweet_id = tweet.tweet_id) as replies,
           tweet.date_time as dateTime
    FROM tweet
    WHERE tweet.user_id = ?
  `,
    [user_id],
  )

  res.json(tweets)
})

// API 10: Create a tweet
app.post('/user/tweets/', authenticateToken, async (req, res) => {
  const {tweet} = req.body
  const {user_id} = req.user
  const db = await dbPromise

  await db.run(
    'INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, datetime("now"))',
    [tweet, user_id],
  )

  res.status(200).json({message: 'Created a Tweet'})
})

// API 11: Delete a tweet by ID
app.delete('/tweets/:tweetId/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params
  const {user_id} = req.user
  const db = await dbPromise

  const tweet = await db.get(
    'SELECT * FROM tweet WHERE tweet_id = ? AND user_id = ?',
    [tweetId, user_id],
  )

  if (!tweet) {
    return res.status(401).json({error: 'Invalid Request'})
  }

  await db.run('DELETE FROM tweet WHERE tweet_id = ?', [tweetId])

  res.status(200).json({message: 'Tweet Removed'})
})

module.exports = app

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
