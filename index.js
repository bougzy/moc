// index.js
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const PORT = process.env.PORT || 3001;

// ========== ENVIRONMENT VALIDATION ==========
console.log('🔍 Checking environment variables...');
console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ Set' : '❌ Missing');
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? '✅ Set' : '❌ Missing');
console.log('FRONTEND_URL:', process.env.FRONTEND_URL || '❌ Missing');

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

// Use environment variable or default - MUST match Google Cloud Console EXACTLY
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 
  `https://moc-iklj.onrender.com/auth/callback`;

console.log('\n🔧 Final Configuration:');
console.log(`   Port: ${PORT}`);
console.log(`   Frontend URL: ${process.env.FRONTEND_URL}`);
console.log(`   Google Redirect URI: ${GOOGLE_REDIRECT_URI}`);

// ========== SESSION CONFIGURATION ==========
app.use(session({
  secret: process.env.SESSION_SECRET || 'render-temp-secret-change-this-in-production',
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
  console.log('🔐 Serializing user:', user.id);
  done(null, {
    id: user.id,
    displayName: user.displayName,
    email: user.email,
    picture: user.picture
  });
});

passport.deserializeUser((obj, done) => {
  console.log('🔓 Deserializing user:', obj.id);
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
    try {
      console.log('\n📨 Google OAuth Callback Received:');
      console.log('   Profile ID:', profile.id);
      console.log('   Display Name:', profile.displayName);
      console.log('   Email:', profile.emails?.[0]?.value || 'No email');
      
      const user = {
        id: profile.id,
        displayName: profile.displayName,
        email: profile.emails && profile.emails[0] ? profile.emails[0].value : null,
        picture: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
        provider: profile.provider,
        accessToken: accessToken,
        refreshToken: refreshToken
      };
      
      console.log(`✅ User authenticated successfully: ${user.email || user.displayName}`);
      
      return done(null, user);
    } catch (error) {
      console.error('❌ Error in Google Strategy callback:', error);
      return done(error, null);
    }
  }
));

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configuration
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = [
    'https://mc-opal.vercel.app',
    'https://moc-iklj.onrender.com',
    'http://localhost:3000',
    'http://localhost:5173'
  ];
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Request logger
app.use((req, res, next) => {
  console.log(`\n🌐 ${new Date().toISOString()} - ${req.method} ${req.url}`);
  console.log('   Origin:', req.headers.origin || 'none');
  console.log('   Query:', req.query);
  next();
});

// ========== ROUTES ==========

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    googleClientId: process.env.GOOGLE_CLIENT_ID?.substring(0, 20) + '...',
    redirectUri: GOOGLE_REDIRECT_URI,
    frontendUrl: process.env.FRONTEND_URL
  });
});

// 1. Initiate Google OAuth login
app.get('/auth/google', (req, res, next) => {
  console.log('\n🚀 Starting Google OAuth flow...');
  console.log('   Redirect URI:', GOOGLE_REDIRECT_URI);
  console.log('   Client ID:', process.env.GOOGLE_CLIENT_ID?.substring(0, 20) + '...');
  
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'consent',
    accessType: 'offline',
    includeGrantedScopes: true
  })(req, res, next);
});

// 2. Handle Google OAuth callback
app.get('/auth/callback',
  (req, res, next) => {
    console.log('\n🔄 Google OAuth Callback Received:');
    console.log('   Query params:', req.query);
    console.log('   Session ID:', req.sessionID);
    
    if (req.query.error) {
      console.error('❌ Google returned error:', req.query.error);
      console.error('   Error description:', req.query.error_description);
      return res.redirect(`${process.env.FRONTEND_URL}?error=${encodeURIComponent(req.query.error)}&description=${encodeURIComponent(req.query.error_description || 'Unknown error')}`);
    }
    
    if (!req.query.code) {
      console.error('❌ No authorization code received');
      return res.redirect(`${process.env.FRONTEND_URL}?error=no_code`);
    }
    
    console.log('✅ Authorization code received');
    next();
  },
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL}?error=auth_failed`,
    failureMessage: true 
  }),
  (req, res) => {
    console.log('\n🎉 Authentication successful!');
    console.log('   User:', req.user.email || req.user.displayName);
    console.log('   User ID:', req.user.id);
    console.log('   Session ID:', req.sessionID);
    
    // Create a success page that redirects to frontend
    const successHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Successful</title>
        <script>
          // Store user info in localStorage
          localStorage.setItem('oauth_user', JSON.stringify({
            id: '${req.user.id}',
            displayName: '${req.user.displayName}',
            email: '${req.user.email}',
            picture: '${req.user.picture}',
            authenticated: true,
            timestamp: '${new Date().toISOString()}'
          }));
          
          // Redirect to frontend
          window.location.href = '${process.env.FRONTEND_URL}/dashboard?auth=success';
        </script>
      </head>
      <body>
        <p>Authentication successful! Redirecting...</p>
      </body>
      </html>
    `;
    
    res.send(successHtml);
  }
);

// 3. Get current user info (protected route)
app.get('/auth/me', (req, res) => {
  console.log('\n🔍 Checking authentication status...');
  console.log('   Session ID:', req.sessionID);
  console.log('   Is authenticated:', req.isAuthenticated());
  
  if (!req.isAuthenticated()) {
    return res.status(401).json({ 
      error: 'Not authenticated',
      authenticated: false 
    });
  }
  
  console.log('✅ User is authenticated:', req.user.email);
  
  const safeUser = {
    id: req.user.id,
    displayName: req.user.displayName,
    email: req.user.email,
    picture: req.user.picture,
    authenticated: true
  };
  
  res.json(safeUser);
});

// 4. Logout endpoints (both GET and POST for flexibility)
app.get('/auth/logout', (req, res) => {
  console.log('\n👋 GET Logout requested...');
  
  req.logout((err) => {
    req.session.destroy((err) => {
      res.clearCookie('google-oauth-session');
      res.redirect(process.env.FRONTEND_URL);
    });
  });
});

app.post('/auth/logout', (req, res) => {
  console.log('\n👋 POST Logout requested...');
  
  req.logout((err) => {
    req.session.destroy((err) => {
      res.clearCookie('google-oauth-session');
      res.json({ success: true, message: 'Logged out successfully' });
    });
  });
});

// Debug endpoint to check session
app.get('/debug/session', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    authenticated: req.isAuthenticated(),
    user: req.user || null,
    session: {
      cookie: req.session.cookie,
      passport: req.session.passport
    }
  });
});

// Debug endpoint to see environment
app.get('/debug/env', (req, res) => {
  const safeEnv = {
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID ? 'Set' : 'Missing',
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET ? 'Set' : 'Missing',
    GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI || 'Missing',
    FRONTEND_URL: process.env.FRONTEND_URL || 'Missing',
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: process.env.PORT || 3001
  };
  
  res.json(safeEnv);
});

// Test OAuth URL generation
app.get('/test/oauth-url', (req, res) => {
  const { OAuth2Client } = require('google-auth-library');
  
  const oauth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI
  );
  
  const authorizeUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
    prompt: 'consent'
  });
  
  res.json({
    authorizeUrl,
    redirectUri: GOOGLE_REDIRECT_URI,
    clientId: process.env.GOOGLE_CLIENT_ID?.substring(0, 20) + '...'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Google OAuth Backend',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      auth: {
        login: '/auth/google',
        callback: '/auth/callback',
        me: '/auth/me',
        logout: '/auth/logout'
      },
      debug: {
        session: '/debug/session',
        env: '/debug/env',
        oauthUrl: '/test/oauth-url'
      }
    }
  });
});

// ========== ERROR HANDLING ==========

// 404 handler
app.use((req, res) => {
  console.error(`❌ 404: ${req.method} ${req.url}`);
  res.status(404).json({ 
    error: 'Not found',
    path: req.path,
    method: req.method,
    availableRoutes: [
      '/',
      '/health',
      '/auth/google',
      '/auth/callback',
      '/auth/me',
      '/auth/logout',
      '/debug/session',
      '/debug/env',
      '/test/oauth-url'
    ]
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Unhandled error:', err);
  
  const statusCode = err.status || err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;
  
  res.status(statusCode).json({
    error: message,
    path: req.path,
    timestamp: new Date().toISOString()
  });
});

// ========== SERVER STARTUP ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
  
██████╗ ███████╗██████╗ ███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                         
🚀 Server is running on Render!
📍 External URL: https://moc-iklj.onrender.com
🔧 Port: ${PORT}
🌐 Frontend URL: ${process.env.FRONTEND_URL}
🔐 Google OAuth configured
🔄 Callback URL: ${GOOGLE_REDIRECT_URI}

📋 Available endpoints:
   GET  /                      ← API info
   GET  /health                ← Health check
   GET  /auth/google           ← Start OAuth flow
   GET  /auth/callback         ← Google redirects here
   GET  /auth/me               ← Check auth status
   GET/POST /auth/logout       ← Log out
   GET  /debug/session         ← Debug session
   GET  /debug/env             ← Debug environment
   GET  /test/oauth-url        ← Test OAuth URL generation

⚠️  CRITICAL VERIFICATION STEPS:
   1. Google Cloud Console → Credentials → OAuth 2.0 Client ID
   2. Authorized redirect URIs MUST include: ${GOOGLE_REDIRECT_URI}
   3. OAuth consent screen → Add your email as a test user
   4. Make sure "Profile" and "Email" scopes are added
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