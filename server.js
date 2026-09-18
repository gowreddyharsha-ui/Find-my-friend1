require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
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

// ---------------------------------------------------------------------------
// CHANGED THIS PASS: no more insecure fallback secret. The server now
// refuses to start at all if JWT_SECRET isn't set to something real. Every
// token created or verified anywhere in this file uses this one constant.
// ---------------------------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set and contain at least 32 characters');
}

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/findmyfriend';

// CHANGED THIS PASS: CORS is now driven by a single CLIENT_ORIGIN env var
// instead of a wildcard "*" (which can't be combined with credentials:true
// anyway — cookies wouldn't be sent cross-origin under a wildcard). Localhost
// is only allowed when explicitly opted into for development.
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || '';
const ALLOW_LOCALHOST_DEV = process.env.ALLOW_LOCALHOST_DEV === 'true';

const allowedOrigins = [];
if (CLIENT_ORIGIN) allowedOrigins.push(CLIENT_ORIGIN);
if (ALLOW_LOCALHOST_DEV) {
  allowedOrigins.push('http://localhost:5000', 'http://localhost:3000');
}

const corsOptions = {
  origin(origin, callback) {
    // No Origin header (curl, server-to-server tools, same-origin page loads)
    // is allowed through; anything else must be explicitly configured.
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true // required so the browser will send/receive the auth cookie
};

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: corsOptions });

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Database model
//
// CHANGED THIS PASS: dropped the `socketId` field. A single string can't
// represent "this user has 3 active connections" (phone + laptop + a second
// tab), which was exactly the multi-device bug being fixed — presence is
// now tracked purely in memory (see `connectedSockets` below), which is the
// right place for something this ephemeral anyway.
// Added light validation on username/location fields.
// ---------------------------------------------------------------------------
const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,30}$/;

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    index: true,
    minlength: 3,
    maxlength: 30,
    match: USERNAME_PATTERN
  },
  password: { type: String, required: true },
  status: { type: String, default: '', maxlength: 200 },
  // Minimum viable friend-request system: plain username arrays on the
  // user document rather than a separate collection, since a user's own
  // friend/request lists are always read and written as a whole.
  friends: { type: [String], default: [] },
  incomingRequests: { type: [String], default: [] }, // usernames who have requested to be this user's friend
  outgoingRequests: { type: [String], default: [] }, // usernames this user has requested
  location: {
    latitude: { type: Number, default: null, min: -90, max: 90 },
    longitude: { type: Number, default: null, min: -180, max: 180 },
    building: { type: String, default: 'Unknown', maxlength: 100 },
    floor: { type: String, default: 'Ground Floor', maxlength: 50 },
    updatedAt: { type: Date, default: null }
  }
});

const User = mongoose.model('User', userSchema);

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function signToken(user) {
  return jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
}

// Tiny manual cookie parser — avoids adding the cookie-parser dependency
// just for this. Express's res.cookie()/clearCookie() work without it.
function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  cookieHeader.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    if (!key) return;
    try {
      out[key] = decodeURIComponent(pair.slice(idx + 1).trim());
    } catch (e) {
      out[key] = pair.slice(idx + 1).trim();
    }
  });
  return out;
}

// CHANGED THIS PASS: the JWT now travels primarily as an HttpOnly cookie
// (so frontend JS can never read it out of localStorage). A Bearer header
// is still accepted as a fallback — useful for API testing tools and for
// not breaking anything if a caller isn't cookie-based.
function getTokenFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.authToken) return cookies.authToken;
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) return header.slice(7);
  return null;
}

function requireAuth(req, res, next) {
  const token = getTokenFromRequest(req);

  if (!token) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Invalid or expired session, please log in again' });
  }
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Presence tracking (in-memory) — a user can have multiple sockets at once
// (phone + laptop + a second tab). A user is only "offline" once every one
// of their sockets has disconnected.
// ---------------------------------------------------------------------------
const connectedSockets = new Map(); // username -> Set<socket.id>

function markSocketOnline(username, socketId) {
  if (!connectedSockets.has(username)) connectedSockets.set(username, new Set());
  connectedSockets.get(username).add(socketId);
  return connectedSockets.get(username).size === 1; // true if this is the user's first active connection
}
function markSocketOffline(username, socketId) {
  const set = connectedSockets.get(username);
  if (!set) return true;
  set.delete(socketId);
  const nowFullyOffline = set.size === 0;
  if (nowFullyOffline) connectedSockets.delete(username);
  return nowFullyOffline;
}
function isUserOnline(username) {
  const set = connectedSockets.get(username);
  return !!set && set.size > 0;
}

// Per-friend subscriptions — CHANGED THIS PASS: previously every location
// update was broadcast to every connected client (io.emit). Now the server
// tracks exactly which sockets are subscribed to which username, and a
// location update only ever reaches those sockets.
const friendSubscribers = new Map(); // targetUsername -> Set<socket.id>

function addSubscriber(targetUsername, socketId) {
  if (!friendSubscribers.has(targetUsername)) friendSubscribers.set(targetUsername, new Set());
  friendSubscribers.get(targetUsername).add(socketId);
}
function removeSubscriber(targetUsername, socketId) {
  const set = friendSubscribers.get(targetUsername);
  if (!set) return;
  set.delete(socketId);
  if (set.size === 0) friendSubscribers.delete(targetUsername);
}
function notifySubscribers(targetUsername, event, payload) {
  const set = friendSubscribers.get(targetUsername);
  if (!set) return;
  for (const sid of set) io.to(sid).emit(event, payload);
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
app.post('/api/auth/register', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';

    if (!USERNAME_PATTERN.test(username)) {
      return res.status(400).json({ error: 'Username must be 3-30 characters (letters, numbers, _ . -)' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: 'Username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// CHANGED THIS PASS: the JWT is no longer returned in the JSON body (that
// would defeat the point of HttpOnly — a frontend could just stash it in
// localStorage again). It's set as an HttpOnly/SameSite cookie instead; the
// browser stores and resends it automatically, JS never touches it.
//
// COOKIE_SAME_SITE/COOKIE_SECURE deployment note: defaults are safe for this
// app's normal setup (server.js serves map.html/login.html itself, so it's
// same-origin — SameSite=Lax works fine). If you ever split the frontend
// onto a different domain from this API, set COOKIE_SAME_SITE=none and make
// sure the site is served over HTTPS (COOKIE_SECURE requires it), and set
// CLIENT_ORIGIN to that exact frontend origin.
const COOKIE_SAME_SITE = process.env.COOKIE_SAME_SITE || 'lax';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';

function setAuthCookie(res, token) {
  res.cookie('authToken', token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAME_SITE,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = signToken(user);
    setAuthCookie(res, token);
    res.json({ username: user.username });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// New: lets the frontend verify (on load, or after a network blip) that its
// cookie session is still valid, without needing to read the cookie itself.
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username });
});

// New: clears the auth cookie. Needed because JS can't delete an HttpOnly
// cookie itself — logout has to ask the server to do it.
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAME_SITE
  });
  res.json({ success: true });
});

// ---------------------------------------------------------------------------
// Search API — requires auth; excluded user comes from the verified JWT.
//
// CHANGED THIS PASS (privacy fix): a search match's location/building/
// floor/address is now ONLY included if the requester and that user are
// accepted friends. Everyone else gets back just the username, online
// status, and friend-request state (so the UI can offer "Add Friend" /
// "Pending" / "Accept") — never location data.
// ---------------------------------------------------------------------------
app.get('/api/search', requireAuth, async (req, res) => {
  try {
    const rawQuery = (req.query.username || '').trim();
    if (!rawQuery) {
      return res.status(400).json({ error: 'Username query is required' });
    }

    const safePattern = escapeRegex(rawQuery);
    const usernameFilter = { $regex: safePattern, $options: 'i', $ne: req.user.username };

    const [meDoc, users] = await Promise.all([
      User.findOne({ username: req.user.username }).select('friends incomingRequests outgoingRequests -_id').lean(),
      User.find({ username: usernameFilter }).select('username location status -_id').limit(20).lean()
    ]);

    const myFriends = new Set(meDoc?.friends || []);
    const myIncoming = new Set(meDoc?.incomingRequests || []); // they requested me
    const myOutgoing = new Set(meDoc?.outgoingRequests || []); // I requested them

    const results = users.map((u) => {
      const isFriend = myFriends.has(u.username);
      const base = {
        username: u.username,
        online: isUserOnline(u.username),
        isFriend,
        requestReceived: myIncoming.has(u.username),
        requestSent: myOutgoing.has(u.username)
      };
      if (isFriend) {
        base.location = u.location;
        base.status = u.status;
      }
      return base;
    });

    res.json(results);
  } catch (error) {
    console.error('Search error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------------------------------------------------------------
// Friend request system (minimum viable):
//   POST /api/friends/request  { username }  — send a request
//   POST /api/friends/accept   { username }  — accept a pending incoming request
//   POST /api/friends/reject   { username }  — reject/withdraw a pending request
//   GET  /api/friends                        — list your friends + requests
// All identify the caller from the verified JWT (req.user.username), never
// from a client-supplied id.
// ---------------------------------------------------------------------------
app.post('/api/friends/request', requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const targetUsername = (req.body.username || '').trim();

    if (!targetUsername || targetUsername === me) {
      return res.status(400).json({ success: false, message: 'Invalid target username' });
    }

    const [meDoc, targetDoc] = await Promise.all([
      User.findOne({ username: me }),
      User.findOne({ username: targetUsername })
    ]);
    if (!targetDoc) return res.status(404).json({ success: false, message: 'User not found' });

    if (meDoc.friends.includes(targetUsername)) {
      return res.status(400).json({ success: false, message: 'Already friends' });
    }
    if (meDoc.incomingRequests.includes(targetUsername)) {
      return res.status(400).json({ success: false, message: `${targetUsername} already sent you a request — accept it instead` });
    }
    if (targetDoc.incomingRequests.includes(me)) {
      return res.status(400).json({ success: false, message: 'Request already sent' });
    }

    targetDoc.incomingRequests.push(me);
    meDoc.outgoingRequests.push(targetUsername);
    await Promise.all([targetDoc.save(), meDoc.save()]);

    res.json({ success: true, message: 'Friend request sent' });
  } catch (err) {
    console.error('Friend request error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/friends/accept', requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const fromUsername = (req.body.username || '').trim();

    const meDoc = await User.findOne({ username: me });
    if (!meDoc.incomingRequests.includes(fromUsername)) {
      return res.status(400).json({ success: false, message: 'No such pending request' });
    }
    const otherDoc = await User.findOne({ username: fromUsername });
    if (!otherDoc) return res.status(404).json({ success: false, message: 'User not found' });

    meDoc.incomingRequests = meDoc.incomingRequests.filter((u) => u !== fromUsername);
    if (!meDoc.friends.includes(fromUsername)) meDoc.friends.push(fromUsername);

    otherDoc.outgoingRequests = otherDoc.outgoingRequests.filter((u) => u !== me);
    if (!otherDoc.friends.includes(me)) otherDoc.friends.push(me);

    await Promise.all([meDoc.save(), otherDoc.save()]);

    res.json({ success: true, message: 'Friend request accepted' });
  } catch (err) {
    console.error('Friend accept error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/friends/reject', requireAuth, async (req, res) => {
  try {
    const me = req.user.username;
    const fromUsername = (req.body.username || '').trim();

    await Promise.all([
      User.findOneAndUpdate({ username: me }, { $pull: { incomingRequests: fromUsername } }),
      User.findOneAndUpdate({ username: fromUsername }, { $pull: { outgoingRequests: me } })
    ]);

    res.json({ success: true, message: 'Friend request rejected' });
  } catch (err) {
    console.error('Friend reject error:', err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/friends', requireAuth, async (req, res) => {
  try {
    const meDoc = await User.findOne({ username: req.user.username })
      .select('friends incomingRequests outgoingRequests -_id')
      .lean();

    res.json({
      friends: meDoc?.friends || [],
      incomingRequests: meDoc?.incomingRequests || [],
      outgoingRequests: meDoc?.outgoingRequests || []
    });
  } catch (err) {
    console.error('Friends list error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------------------------------------------------------------
// Account management — single route each, identity from req.user.username.
// ---------------------------------------------------------------------------
app.post('/update-account', requireAuth, async (req, res) => {
  try {
    const { status, password } = req.body;

    if (status === undefined && !password) {
      return res.status(400).json({ success: false, message: 'Nothing to update' });
    }
    if (password && password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }

    const updateFields = {};
    if (status !== undefined) updateFields.status = String(status).slice(0, 200);
    if (password) updateFields.password = await bcrypt.hash(password, 10);

    const updatedUser = await User.findOneAndUpdate(
      { username: req.user.username },
      { $set: updateFields },
      { new: true }
    ).select('username status');

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, message: 'Account updated successfully', user: updatedUser });
  } catch (err) {
    console.error('Update error:', err.message);
    res.status(500).json({ success: false, message: 'Server error during update' });
  }
});

// CHANGED THIS PASS: disconnects EVERY active socket for this user (not
// just one device), across the friendSubscribers/connectedSockets maps.
// The JWT itself can't be "revoked" (it's stateless), but the Socket.IO
// handshake middleware below re-checks that the account still exists on
// every (re)connection attempt, so a stale token can't be used to
// reconnect once the account is gone.
app.post('/delete-account', requireAuth, async (req, res) => {
  try {
    const deletedUser = await User.findOneAndDelete({ username: req.user.username });

    if (!deletedUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const socketIds = connectedSockets.get(req.user.username);
    if (socketIds) {
      for (const sid of Array.from(socketIds)) {
        const sock = io.sockets.sockets.get(sid);
        if (sock) {
          sock.emit('account_deleted');
          if (sock.subscribedFriend) removeSubscriber(sock.subscribedFriend, sock.id);
          sock.disconnect(true);
        }
      }
      connectedSockets.delete(req.user.username);
    }
    friendSubscribers.delete(req.user.username); // no one can still "subscribe" to a deleted account

    // Clean up dangling references so a deleted username doesn't linger in
    // anyone else's friends/requests lists.
    await User.updateMany(
      {},
      {
        $pull: {
          friends: req.user.username,
          incomingRequests: req.user.username,
          outgoingRequests: req.user.username
        }
      }
    );

    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (err) {
    console.error('Delete error:', err.message);
    res.status(500).json({ success: false, message: 'Server error during deletion' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------------------
// Socket.IO
//
// CHANGED THIS PASS: authentication now happens once, in a handshake
// middleware, using the JWT — not via a client-sent `authenticate` event
// after connecting. `socket.username` is the ONLY source of identity for
// everything that follows; nothing from event payloads is ever trusted for
// identity. The middleware also confirms the account still exists in the
// database, so a token from a deleted account is rejected on (re)connect.
// ---------------------------------------------------------------------------
function getSocketToken(socket) {
  const cookies = parseCookies(socket.handshake.headers.cookie);
  if (cookies.authToken) return cookies.authToken;
  return socket.handshake.auth?.token || null; // fallback, kept for compatibility
}

io.use(async (socket, next) => {
  try {
    const token = getSocketToken(socket);
    if (!token) {
      return next(new Error('Authentication required'));
    }

    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload?.username) {
      return next(new Error('Invalid authentication token'));
    }

    const user = await User.findOne({ username: payload.username }).select('_id').lean();
    if (!user) {
      return next(new Error('Account no longer exists'));
    }

    socket.username = payload.username;
    next();
  } catch (err) {
    next(new Error('Invalid or expired authentication token'));
  }
});

const MIN_UPDATE_INTERVAL_MS = 2000;
const lastUpdateAt = new Map(); // socket.id -> timestamp

io.on('connection', (socket) => {
  console.log(`Authenticated connection: ${socket.username} (${socket.id})`);
  socket.subscribedFriend = null;

  const becameOnline = markSocketOnline(socket.username, socket.id);
  if (becameOnline) {
    notifySubscribers(socket.username, 'presence_update', { username: socket.username, online: true });
  }

  // CHANGED THIS PASS (privacy fix): subscribing to someone's live location
  // now requires an accepted friendship, checked fresh against the database
  // every time — never trusted from anything the client claims. On success,
  // the current/last-known location and presence are sent immediately (this
  // is also what makes "get the latest friend location" work right after a
  // reconnect, since the frontend re-subscribes on every reconnect).
  socket.on('subscribe_friend', async (targetUsername) => {
    if (typeof targetUsername !== 'string' || !targetUsername) return;
    try {
      const meDoc = await User.findOne({ username: socket.username }).select('friends -_id').lean();
      if (!meDoc || !meDoc.friends.includes(targetUsername)) {
        socket.emit('subscribe_denied', { username: targetUsername, message: 'You are not friends with this user' });
        return;
      }

      if (socket.subscribedFriend) removeSubscriber(socket.subscribedFriend, socket.id);
      socket.subscribedFriend = targetUsername;
      addSubscriber(targetUsername, socket.id);

      const friendDoc = await User.findOne({ username: targetUsername }).select('location -_id').lean();
      if (friendDoc && friendDoc.location && typeof friendDoc.location.latitude === 'number') {
        socket.emit('location_update', { username: targetUsername, location: friendDoc.location });
      }
      socket.emit('presence_update', { username: targetUsername, online: isUserOnline(targetUsername) });
    } catch (err) {
      console.error('subscribe_friend error:', err.message);
    }
  });

  socket.on('unsubscribe_friend', () => {
    if (socket.subscribedFriend) {
      removeSubscriber(socket.subscribedFriend, socket.id);
      socket.subscribedFriend = null;
    }
  });

  // CHANGED THIS PASS: accepts an optional ack callback so the client can
  // tell the difference between "sent" and "the server actually saved it" —
  // needed so the offline queue only clears on confirmed storage, not on
  // fire-and-forget emit.
  socket.on('update_location', async (data, ack) => {
    const respond = (payload) => { if (typeof ack === 'function') ack(payload); };
    try {
      const { latitude, longitude, building, floor } = data || {};

      if (
        typeof latitude !== 'number' || Number.isNaN(latitude) || latitude < -90 || latitude > 90 ||
        typeof longitude !== 'number' || Number.isNaN(longitude) || longitude < -180 || longitude > 180
      ) {
        return respond({ success: false, error: 'Invalid coordinates' });
      }

      const now = Date.now();
      const last = lastUpdateAt.get(socket.id) || 0;
      if (now - last < MIN_UPDATE_INTERVAL_MS) {
        return respond({ success: false, error: 'Throttled', retryAfterMs: MIN_UPDATE_INTERVAL_MS - (now - last) });
      }
      lastUpdateAt.set(socket.id, now);

      const updatedLocation = {
        latitude,
        longitude,
        building: (typeof building === 'string' ? building : 'Unknown').slice(0, 100),
        floor: (typeof floor === 'string' ? floor : 'Ground Floor').slice(0, 50),
        updatedAt: new Date()
      };

      await User.findOneAndUpdate({ username: socket.username }, { location: updatedLocation });

      notifySubscribers(socket.username, 'location_update', { username: socket.username, location: updatedLocation });
      respond({ success: true });
    } catch (err) {
      console.error('Location update error:', err.message);
      respond({ success: false, error: 'Server error' });
    }
  });

  socket.on('disconnect', () => {
    lastUpdateAt.delete(socket.id);
    if (socket.subscribedFriend) {
      removeSubscriber(socket.subscribedFriend, socket.id);
      socket.subscribedFriend = null;
    }

    const fullyOffline = markSocketOffline(socket.username, socket.id);
    if (fullyOffline) {
      // Only announce "offline" once every device/tab for this user has disconnected.
      notifySubscribers(socket.username, 'presence_update', { username: socket.username, online: false });
      console.log(`User ${socket.username} fully disconnected`);
    } else {
      console.log(`One connection for ${socket.username} closed; other sessions still active`);
    }
  });
});

// ---------------------------------------------------------------------------
// Server startup & DB connection
// ---------------------------------------------------------------------------
  mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => console.error('Database connection error:', err));
