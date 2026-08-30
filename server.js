const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception thrown:', error);
});
const app = express();
const path = require('path');

//app.use(express.static(path.join(__dirname, '../public')));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Database Model ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  location: {
    latitude: { type: Number, default: 0 },
    longitude: { type: Number, default: 0 },
    building: { type: String, default: "Unknown" },
    floor: { type: Number, default: 0 },
    updatedAt: { type: Date, default: Date.now }
  },
  socketId: { type: String, default: null }
});

const User = mongoose.model('User', userSchema);

// --- Authentication Routes ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET || 'fallbacksecret', { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Search API ---
app.get('/api/search', async (req, res) => {
    try {
        const query = req.query.username;
        if (!query) {
            return res.status(400).json({ error: "Username query is required" });
        }

        const users = await User.find({ 
            username: { $regex: query, $options: 'i' },
            username: { $ne: req.query.currentUser }
        }).select('username location');

        res.json(users);
    } catch (error) {
        res.status(500).json({ error: "Server error" });
    }
});
// --- DELETE ACCOUNT ROUTE ---
app.post('/api/delete-account', async (req, res) => {
    try {
        const { username } = req.body;
        
        // Find and delete the user from the MongoDB database
        const deletedUser = await User.findOneAndDelete({ username: username });
        
        if (deletedUser) {
            res.json({ success: true, message: 'Account deleted' });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (err) {
        console.error('Error deleting account:', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// --- Socket.io Real-Time Tracking ---
io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);

  socket.on('authenticate', async ({ username }) => {
    try {
      await User.findOneAndUpdate({ username }, { socketId: socket.id });
      socket.username = username;
      console.log(`User ${username} linked with socket ${socket.id}`);
    } catch (err) {
      console.error("Auth socket error:", err.message);
    }
  });

  socket.on('update_location', async (data) => {
    try {
      const { username, latitude, longitude, building, floor } = data;
      const updatedLocation = {
        latitude: latitude,
        longitude: longitude,
        building: building || "Unknown",
        floor: floor !== undefined ? floor : 0,
        updatedAt: Date.now()
      };

      await User.findOneAndUpdate({ username }, { location: updatedLocation });
      io.emit('location_update', { username, location: updatedLocation });
    } catch (err) {
      console.error("Location update error:", err.message);
    }
  });

  socket.on('disconnect', async () => {
    if (socket.username) {
      await User.findOneAndUpdate({ username: socket.username }, { socketId: null });
      console.log(`User ${socket.username} disconnected`);
    }
  });
});

// --- Server Startup & DB Connection ---
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/findmyfriend';

//app.get('/api', (req, res) => {
 // res.send('Find My Friend API is running successfully!');
//});

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("Connected to MongoDB");
    server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => console.error("Database connection error:", err));