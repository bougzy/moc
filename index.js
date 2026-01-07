// index.js
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const PORT = process.env.PORT || 3001;

// ========== ENVIRONMENT VALIDATION ==========
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

// IMPORTANT: This MUST match exactly what's in Google Cloud Console
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 
  `https://moc-iklj.onrender.com/auth/callback`; // Changed to /auth/callback

console.log('🔧 Configuration:');
console.log(`   Port: ${PORT}`);
console.log(`   Frontend URL: ${process.env.FRONTEND_URL}`);
console.log(`   Google Redirect URI: ${GOOGLE_REDIRECT_URI}`);

// ========== SESSION CONFIGURATION ==========
app.use(session({
  secret: process.env.SESSION_SECRET || 'temporary-development-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // Render uses HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  },
  name: 'google-oauth-session'
}));

// ========== PASSPORT INITIALIZATION ==========
app.use(passport.initialize());
app.use(passport.session());

// ========== USER SERIALIZATION ==========
passport.serializeUser((user, done) => {
  done(null, {
    id: user.id,
    displayName: user.displayName,
    email: user.email,
    picture: user.picture
  });
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// ========== GOOGLE STRATEGY CONFIGURATION ==========
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_REDIRECT_URI, // This matches Google Cloud Console
    passReqToCallback: false
  },
  (accessToken, refreshToken, profile, done) => {
    console.log('📨 Google OAuth callback received:', profile.id);
    
    const user = {
      id: profile.id,
      displayName: profile.displayName,
      email: profile.emails && profile.emails[0] ? profile.emails[0].value : null,
      picture: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
      provider: profile.provider,
      accessToken: accessToken,
      refreshToken: refreshToken
    };
    
    console.log(`✅ User authenticated: ${user.email || user.displayName}`);
    
    return done(null, user);
  }
));

// ========== MIDDLEWARE ==========
app.use(express.json());

// CORS configuration
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Allow multiple origins
  const allowedOrigins = [
    'https://mc-opal.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173',
    'https://moc-iklj.onrender.com'
  ];
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Request logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.headers.origin || 'none'}`);
  next();
});

// ========== ROUTES ==========

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    service: 'google-oauth-backend',
    routes: [
      '/auth/google',
      '/auth/callback',
      '/auth/me',
      '/auth/logout'
    ]
  });
});

// 1. Initiate Google OAuth login
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'consent', // Changed from 'select_account' to 'consent'
    accessType: 'offline'
  })
);

// 2. Handle Google OAuth callback - THIS IS THE FIXED ROUTE
// Changed from /auth/google/callback to /auth/callback
app.get('/auth/callback',
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL}?error=auth_failed`,
    failureMessage: true
  }),
  (req, res) => {
    console.log(`🎉 Authentication successful! User: ${req.user.email || req.user.displayName}`);
    
    // For now, redirect to frontend - frontend should handle storing the session
    res.redirect(`${process.env.FRONTEND_URL}/dashboard?auth=success`);
  }
);

// 3. Get current user info (protected route)
app.get('/auth/me', (req, res) => {
  console.log('🔍 Checking authentication status for session:', req.sessionID);
  
  if (!req.isAuthenticated()) {
    console.log('❌ User not authenticated');
    return res.status(401).json({ 
      error: 'Not authenticated',
      authenticated: false 
    });
  }
  
  console.log('✅ User authenticated:', req.user.email);
  
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
    console.log(`👋 User logging out: ${req.user.email || req.user.displayName}`);
  }
  
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
      
      res.clearCookie('google-oauth-session');
      res.json({ success: true, message: 'Logged out successfully' });
    });
  });
});

// Debug endpoint to check session
app.get('/debug/session', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    session: req.session,
    authenticated: req.isAuthenticated(),
    user: req.user || null
  });
});

// ========== ERROR HANDLING ==========

// 404 handler
app.use((req, res) => {
  console.error(`404: ${req.method} ${req.url}`);
  res.status(404).json({ 
    error: 'Not found',
    path: req.path,
    method: req.method,
    availableRoutes: [
      '/health',
      '/auth/google',
      '/auth/callback', // This is now the correct route
      '/auth/me',
      '/auth/logout',
      '/debug/session'
    ]
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Unhandled error:', err);
  
  const statusCode = err.status || err.statusCode || 500;
  const message = statusCode === 500 ? 'Internal server error' : err.message;
  
  res.status(statusCode).json({
    error: message,
    path: req.path,
    timestamp: new Date().toISOString()
  });
});

// ========== SERVER STARTUP ==========
app.listen(PORT, () => {
  console.log(`
🚀 Server is running on Render!
📍 URL: https://moc-iklj.onrender.com
🔧 Port: ${PORT}
🌐 Frontend URL: ${process.env.FRONTEND_URL}
🔐 Google OAuth Client ID: ${process.env.GOOGLE_CLIENT_ID?.substring(0, 20)}...
🔄 Callback URL: ${GOOGLE_REDIRECT_URI}

📋 Available endpoints:
   GET  /health
   GET  /auth/google           ← Start OAuth flow
   GET  /auth/callback         ← Google redirects here (MUST match Google Cloud Console)
   GET  /auth/me               ← Check if user is authenticated
   POST /auth/logout           ← Log out user
   GET  /debug/session         ← Debug session info

⚠️  IMPORTANT: Make sure Google Cloud Console has this exact callback URL:
   ${GOOGLE_REDIRECT_URI}
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});