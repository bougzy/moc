// index.js
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const PORT = process.env.PORT || 3000;

// ========== ENVIRONMENT VALIDATION ==========
// Validate required environment variables
const requiredEnvVars = [
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'FRONTEND_URL'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Use PORT from environment or default
// const PORT = process.env.PORT || 3000;

// Construct redirect URI - prioritize explicit setting, otherwise derive from environment
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 
  (process.env.RENDER_EXTERNAL_URL ? `${process.env.RENDER_EXTERNAL_URL}/auth/google/callback` : 
   `http://localhost:${PORT}/auth/google/callback`);

console.log('🔧 Configuration:');
console.log(`   Port: ${PORT}`);
console.log(`   Frontend URL: ${process.env.FRONTEND_URL}`);
console.log(`   Google Redirect URI: ${GOOGLE_REDIRECT_URI}`);

// ========== SESSION CONFIGURATION ==========
// Configure secure session management
app.use(session({
  secret: process.env.SESSION_SECRET || 'temporary-development-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    httpOnly: true, // Prevent client-side JS from accessing the cookie
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'lax' : 'strict'
  },
  name: 'google-oauth-session' // Custom session cookie name
}));

// ========== PASSPORT INITIALIZATION ==========
app.use(passport.initialize());
app.use(passport.session());

// ========== USER SERIALIZATION ==========
// Since we're not using a database, we'll store minimal user info in the session
passport.serializeUser((user, done) => {
  // Store only essential user info in the session
  done(null, {
    id: user.id,
    displayName: user.displayName,
    email: user.email,
    picture: user.picture
  });
});

passport.deserializeUser((obj, done) => {
  // Retrieve user from session
  done(null, obj);
});

// ========== GOOGLE STRATEGY CONFIGURATION ==========
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_REDIRECT_URI,
    passReqToCallback: false
  },
  (accessToken, refreshToken, profile, done) => {
    // This is where you would typically save user to database
    // For this implementation, we just pass the profile info
    
    // Extract essential user information from Google profile
    const user = {
      id: profile.id,
      displayName: profile.displayName,
      email: profile.emails && profile.emails[0] ? profile.emails[0].value : null,
      picture: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
      provider: profile.provider,
      accessToken: accessToken, // Store access token for API calls if needed
      refreshToken: refreshToken // Store refresh token if available
    };
    
    // You could add additional logic here to validate or process the user
    console.log(`✅ User authenticated: ${user.email || user.displayName}`);
    
    return done(null, user);
  }
));

// ========== MIDDLEWARE ==========
// Parse JSON requests
app.use(express.json());

// CORS configuration - allow frontend to access the API
app.use((req, res, next) => {
  const allowedOrigins = [process.env.FRONTEND_URL];
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Simple request logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ========== ROUTES ==========

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    service: 'google-oauth-backend'
  });
});

// 1. Initiate Google OAuth login
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account', // Force account selection
    accessType: 'offline', // Request refresh token
    includeGrantedScopes: true
  })
);

// 2. Handle Google OAuth callback
app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=auth_failed`,
    failureMessage: true
  }),
  (req, res) => {
    // Successful authentication
    console.log(`✅ Authentication successful for user: ${req.user.email || req.user.displayName}`);
    
    // Redirect to frontend with success
    res.redirect(`${process.env.FRONTEND_URL}/login/success`);
  }
);

// 3. Get current user info (protected route)
app.get('/auth/me', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ 
      error: 'Not authenticated',
      authenticated: false 
    });
  }
  
  // Return user info (excluding sensitive tokens unless needed)
  const safeUser = {
    id: req.user.id,
    displayName: req.user.displayName,
    email: req.user.email,
    picture: req.user.picture,
    authenticated: true
  };
  
  res.json(safeUser);
});

// 4. Logout endpoint
app.post('/auth/logout', (req, res) => {
  if (req.isAuthenticated()) {
    console.log(`👋 User logged out: ${req.user.email || req.user.displayName}`);
  }
  
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    
    // Destroy session
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
      
      // Clear session cookie
      res.clearCookie('google-oauth-session');
      
      res.json({ success: true, message: 'Logged out successfully' });
    });
  });
});

// ========== ERROR HANDLING ==========

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not found',
    path: req.path,
    method: req.method 
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Unhandled error:', err);
  
  // Determine status code
  const statusCode = err.status || err.statusCode || 500;
  
  // Security: Don't expose internal errors in production
  const message = process.env.NODE_ENV === 'production' && statusCode === 500
    ? 'Internal server error'
    : err.message || 'Something went wrong';
  
  res.status(statusCode).json({
    error: message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

// ========== SERVER STARTUP ==========
app.listen(PORT, () => {
  console.log(`
🚀 Server is running!
📍 Local: http://localhost:${PORT}
🌐 Frontend: ${process.env.FRONTEND_URL}
🔐 Google OAuth configured with Client ID: ${process.env.GOOGLE_CLIENT_ID?.substring(0, 15)}...
🔄 Callback URL: ${GOOGLE_REDIRECT_URI}

📋 Available endpoints:
   GET  /health
   GET  /auth/google
   GET  /auth/google/callback
   GET  /auth/me
   POST /auth/logout
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});