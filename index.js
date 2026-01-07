// index.js
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const PORT = process.env.PORT || 3001;

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

// Use explicit redirect URI or default
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 
  `https://moc-iklj.onrender.com/auth/callback`;

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
    secure: true, // Render uses HTTPS, so this should be true
    httpOnly: true, // Prevent client-side JS from accessing the cookie
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax' // Use 'lax' for cross-origin requests
  },
  name: 'google-oauth-session' // Custom session cookie name
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
    callbackURL: GOOGLE_REDIRECT_URI,
    passReqToCallback: false
  },
  (accessToken, refreshToken, profile, done) => {
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
  const allowedOrigins = [
    'https://mc-opal.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173'
  ];
  
  const origin = req.headers.origin;
  
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

// OPTION 1: If you want to keep the route as /auth/google/callback
// Add a redirect from /auth/callback to /auth/google/callback
app.get('/auth/callback', (req, res) => {
  // Redirect to the correct callback endpoint
  res.redirect('/auth/google/callback');
});

// 1. Initiate Google OAuth login
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account',
    accessType: 'offline'
  })
);

// 2. Handle Google OAuth callback
app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=auth_failed`,
    failureMessage: true
  }),
  (req, res) => {
    console.log(`✅ Authentication successful for user: ${req.user.email || req.user.displayName}`);
    
    // Create a simple success page for testing
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Successful</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          }
          .container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
          }
          .success-icon {
            color: #10B981;
            font-size: 4rem;
            margin-bottom: 1rem;
          }
          h1 {
            color: #1F2937;
            margin-bottom: 1rem;
          }
          p {
            color: #6B7280;
            margin-bottom: 2rem;
          }
          .user-info {
            background: #F3F4F6;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 2rem;
            text-align: left;
          }
          .btn {
            display: inline-block;
            background: #3B82F6;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 5px;
            text-decoration: none;
            font-weight: 500;
            transition: background 0.3s;
          }
          .btn:hover {
            background: #2563EB;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success-icon">✓</div>
          <h1>Authentication Successful!</h1>
          <p>You have successfully logged in with Google.</p>
          
          <div class="user-info">
            <p><strong>Name:</strong> ${req.user.displayName}</p>
            <p><strong>Email:</strong> ${req.user.email}</p>
          </div>
          
          <a href="${process.env.FRONTEND_URL}" class="btn">Go to Frontend</a>
          
          <script>
            // Store user info in localStorage and redirect
            localStorage.setItem('user', JSON.stringify({
              id: '${req.user.id}',
              displayName: '${req.user.displayName}',
              email: '${req.user.email}',
              picture: '${req.user.picture}',
              authenticated: true
            }));
            
            // Redirect after 3 seconds
            setTimeout(() => {
              window.location.href = '${process.env.FRONTEND_URL}';
            }, 3000);
          </script>
        </div>
      </body>
      </html>
    `);
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
    
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
      
      res.clearCookie('google-oauth-session');
      res.json({ success: true, message: 'Logged out successfully' });
    });
  });
});

// Debug endpoint to see all routes
app.get('/debug/routes', (req, res) => {
  const routes = [];
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      routes.push({
        path: middleware.route.path,
        methods: Object.keys(middleware.route.methods)
      });
    }
  });
  
  res.json({ routes });
});

// ========== ERROR HANDLING ==========

// 404 handler
app.use((req, res) => {
  console.error(`404: ${req.method} ${req.url}`);
  res.status(404).json({ 
    error: 'Not found',
    path: req.path,
    method: req.method,
    availableRoutes: ['/health', '/auth/google', '/auth/google/callback', '/auth/callback', '/auth/me', '/auth/logout', '/debug/routes']
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Unhandled error:', err);
  
  const statusCode = err.status || err.statusCode || 500;
  const message = statusCode === 500 ? 'Internal server error' : err.message;
  
  res.status(statusCode).json({
    error: message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

// ========== SERVER STARTUP ==========
app.listen(PORT, () => {
  console.log(`
🚀 Server is running!
📍 Port: ${PORT}
🌐 Frontend URL: ${process.env.FRONTEND_URL}
🔐 Google OAuth configured with Client ID: ${process.env.GOOGLE_CLIENT_ID?.substring(0, 15)}...
🔄 Callback URL: ${GOOGLE_REDIRECT_URI}

📋 Available endpoints:
   GET  /health
   GET  /auth/google
   GET  /auth/google/callback
   GET  /auth/callback (redirects to /auth/google/callback)
   GET  /auth/me
   POST /auth/logout
   GET  /debug/routes
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