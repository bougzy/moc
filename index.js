// index.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const { google } = require('googleapis');
const { OAuth2 } = google.auth;
const WebSocket = require('ws');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://mc-opal.vercel.app',
  credentials: true
}));
app.use(express.json());

// In-memory storage (ephemeral, cleared on server restart/session end)
const sessions = new Map(); // sessionId -> sessionData
const adminSessions = new Map(); // adminId -> { tokens, activeMeetings }
const meetingSessions = new Map(); // meetingId -> meetingData
const activeConnections = new Map(); // clientId -> WebSocket connection

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'https://moc-iklj.onrender.com/auth/callback';

const oauth2Client = new OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

// Scopes requested
const SCOPES = [
  'https://www.googleapis.com/auth/calendar',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/meetings.space.created'
];

// Helper function to generate unique IDs
const generateId = () => crypto.randomBytes(16).toString('hex');

// Helper function to validate Google Meet links
const validateMeetLink = (link) => {
  try {
    const url = new URL(link);
    if (url.hostname !== 'meet.google.com') {
      return { valid: false, error: 'Invalid domain. Must be meet.google.com' };
    }
    
    // Extract meeting code (e.g., abc-defg-hij from meet.google.com/abc-defg-hij)
    const pathParts = url.pathname.split('/').filter(p => p);
    if (pathParts.length !== 1) {
      return { valid: false, error: 'Invalid Meet URL format' };
    }
    
    const meetingCode = pathParts[0];
    if (!meetingCode.match(/^[a-z]{3}-[a-z]{4}-[a-z]{3}$/i)) {
      return { valid: false, error: 'Invalid meeting code format' };
    }
    
    return { 
      valid: true, 
      meetingCode: meetingCode.toLowerCase(),
      fullUrl: link 
    };
  } catch (error) {
    return { valid: false, error: 'Invalid URL format' };
  }
};

// Authentication endpoints
app.get('/auth/url', (req, res) => {
  try {
    const authUrl = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: SCOPES,
      prompt: 'consent'
    });
    
    res.json({ authUrl });
  } catch (error) {
    console.error('Auth URL generation error:', error);
    res.status(500).json({ error: 'Failed to generate authentication URL' });
  }
});

app.post('/auth/token', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Authorization code required' });
    }
    
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    
    // Get user info to identify admin
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const userInfo = await oauth2.userinfo.get();
    
    const adminId = userInfo.data.id;
    const sessionId = generateId();
    
    // Store admin session in memory
    adminSessions.set(adminId, {
      tokens,
      oauth2Client: oauth2Client,
      createdAt: Date.now(),
      activeMeetings: new Set()
    });
    
    // Store user session
    sessions.set(sessionId, {
      adminId,
      userInfo: userInfo.data,
      lastActive: Date.now()
    });
    
    res.json({ 
      sessionId,
      userInfo: userInfo.data,
      tokens: {
        access_token: tokens.access_token,
        expiry_date: tokens.expiry_date
      }
    });
  } catch (error) {
    console.error('Token exchange error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

app.post('/auth/refresh', async (req, res) => {
  try {
    const { sessionId } = req.body;
    
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session not found' });
    }
    
    const adminSession = adminSessions.get(session.adminId);
    if (!adminSession) {
      return res.status(401).json({ error: 'Admin session expired' });
    }
    
    const { tokens } = await adminSession.oauth2Client.refreshAccessToken();
    adminSession.tokens = tokens;
    adminSession.oauth2Client.setCredentials(tokens);
    
    res.json({ 
      access_token: tokens.access_token,
      expiry_date: tokens.expiry_date
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

app.post('/auth/logout', (req, res) => {
  try {
    const { sessionId } = req.body;
    
    const session = sessions.get(sessionId);
    if (session) {
      const adminSession = adminSessions.get(session.adminId);
      if (adminSession) {
        // Clean up all meetings for this admin
        adminSession.activeMeetings.forEach(meetingId => {
          meetingSessions.delete(meetingId);
        });
        adminSessions.delete(session.adminId);
      }
      sessions.delete(sessionId);
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Meeting management endpoints
app.post('/meetings/add', async (req, res) => {
  try {
    const { sessionId, meetLink, meetingTitle, scheduledTime, timeZone = 'UTC' } = req.body;
    
    // Validate session
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session expired. Please reauthenticate.' });
    }
    
    const adminSession = adminSessions.get(session.adminId);
    if (!adminSession) {
      return res.status(401).json({ error: 'Admin session expired' });
    }
    
    // Validate Meet link
    const validation = validateMeetLink(meetLink);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }
    
    const meetingId = generateId();
    const meetingCode = validation.meetingCode;
    
    // Create meeting session in memory
    const meetingData = {
      meetingId,
      meetingCode,
      meetLink: validation.fullUrl,
      adminId: session.adminId,
      title: meetingTitle || `Meeting ${meetingCode}`,
      status: 'scheduled',
      scheduledTime: scheduledTime ? new Date(scheduledTime).toISOString() : null,
      timeZone,
      createdAt: Date.now(),
      lastUpdated: Date.now(),
      monitoring: false,
      calendarEventId: null,
      remindersSent: [],
      botParticipantId: null,
      lifecycle: {
        scheduled: scheduledTime ? new Date(scheduledTime).toISOString() : null,
        live: null,
        ended: null
      }
    };
    
    meetingSessions.set(meetingId, meetingData);
    
    // Create calendar event if scheduled time provided
    let calendarEvent = null;
    if (scheduledTime) {
      try {
        const calendar = google.calendar({ version: 'v3', auth: adminSession.oauth2Client });
        
        const event = {
          summary: meetingTitle || `Google Meet: ${meetingCode}`,
          description: `Google Meet Link: ${validation.fullUrl}`,
          start: {
            dateTime: new Date(scheduledTime).toISOString(),
            timeZone: timeZone
          },
          end: {
            dateTime: new Date(new Date(scheduledTime).getTime() + 3600000).toISOString(), // 1 hour default
            timeZone: timeZone
          },
          conferenceData: {
            createRequest: {
              requestId: meetingId,
              conferenceSolutionKey: { type: 'hangoutsMeet' }
            }
          },
          reminders: {
            useDefault: false,
            overrides: [
              { method: 'email', minutes: 30 },
              { method: 'popup', minutes: 10 }
            ]
          }
        };
        
        const response = await calendar.events.insert({
          calendarId: 'primary',
          resource: event,
          conferenceDataVersion: 1,
          sendUpdates: 'all'
        });
        
        meetingData.calendarEventId = response.data.id;
        meetingData.meetLink = response.data.hangoutLink || validation.fullUrl;
        calendarEvent = response.data;
        
        // Schedule reminder emails
        scheduleMeetingReminders(meetingId, scheduledTime, timeZone);
        
      } catch (calendarError) {
        console.error('Calendar creation error:', calendarError);
        // Continue without calendar event - meeting can still be monitored
      }
    }
    
    // Notify all connected clients for this admin
    notifyAdmin(session.adminId, 'meeting_added', { meetingId, ...meetingData });
    
    res.json({
      meetingId,
      ...meetingData,
      calendarEvent
    });
    
  } catch (error) {
    console.error('Add meeting error:', error);
    res.status(500).json({ error: 'Failed to add meeting' });
  }
});

app.post('/meetings/start-monitoring', async (req, res) => {
  try {
    const { sessionId, meetingId } = req.body;
    
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session expired' });
    }
    
    const meeting = meetingSessions.get(meetingId);
    if (!meeting) {
      return res.status(404).json({ error: 'Meeting not found' });
    }
    
    if (meeting.adminId !== session.adminId) {
      return res.status(403).json({ error: 'Unauthorized to monitor this meeting' });
    }
    
    if (meeting.monitoring) {
      return res.status(400).json({ error: 'Meeting is already being monitored' });
    }
    
    // Start monitoring
    meeting.monitoring = true;
    meeting.lastUpdated = Date.now();
    
    // In a real implementation, you would:
    // 1. Join the meeting as a bot participant (with disabled mic/camera)
    // 2. Monitor meeting lifecycle events
    // 3. Update status based on actual meeting state
    
    // For now, simulate status updates
    meeting.status = 'live';
    meeting.lifecycle.live = new Date().toISOString();
    
    // Notify admin via email
    sendEmailNotification(
      session.adminId,
      `Meeting "${meeting.title}" is now live`,
      `Your Google Meet session "${meeting.title}" has started.\n\nJoin: ${meeting.meetLink}`
    );
    
    // Notify connected clients
    notifyAdmin(session.adminId, 'meeting_updated', meeting);
    
    // Start periodic status checks (in real implementation)
    startMeetingHealthCheck(meetingId);
    
    res.json({ success: true, meeting });
    
  } catch (error) {
    console.error('Start monitoring error:', error);
    res.status(500).json({ error: 'Failed to start monitoring' });
  }
});

app.post('/meetings/stop-monitoring', (req, res) => {
  try {
    const { sessionId, meetingId } = req.body;
    
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session expired' });
    }
    
    const meeting = meetingSessions.get(meetingId);
    if (!meeting) {
      return res.status(404).json({ error: 'Meeting not found' });
    }
    
    if (meeting.adminId !== session.adminId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Stop monitoring
    meeting.monitoring = false;
    meeting.status = 'ended';
    meeting.lifecycle.ended = new Date().toISOString();
    meeting.lastUpdated = Date.now();
    
    // In real implementation: Leave the meeting as bot participant
    
    // Notify admin via email
    const adminSession = adminSessions.get(session.adminId);
    if (adminSession) {
      sendEmailNotification(
        session.adminId,
        `Meeting "${meeting.title}" monitoring stopped`,
        `Monitoring for "${meeting.title}" has been stopped.\n\nMeeting ended at: ${new Date().toLocaleString()}`
      );
    }
    
    // Notify connected clients
    notifyAdmin(session.adminId, 'meeting_updated', meeting);
    
    // Clean up after delay
    setTimeout(() => {
      meetingSessions.delete(meetingId);
      if (adminSession) {
        adminSession.activeMeetings.delete(meetingId);
      }
      notifyAdmin(session.adminId, 'meeting_removed', { meetingId });
    }, 300000); // Clean up after 5 minutes
    
    res.json({ success: true, meeting });
    
  } catch (error) {
    console.error('Stop monitoring error:', error);
    res.status(500).json({ error: 'Failed to stop monitoring' });
  }
});

app.post('/meetings/remove', (req, res) => {
  try {
    const { sessionId, meetingId } = req.body;
    
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session expired' });
    }
    
    const meeting = meetingSessions.get(meetingId);
    if (!meeting) {
      return res.status(404).json({ error: 'Meeting not found' });
    }
    
    if (meeting.adminId !== session.adminId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Remove from calendar if exists
    if (meeting.calendarEventId) {
      const adminSession = adminSessions.get(session.adminId);
      if (adminSession) {
        google.calendar({ version: 'v3', auth: adminSession.oauth2Client })
          .events.delete({
            calendarId: 'primary',
            eventId: meeting.calendarEventId
          })
          .catch(err => console.error('Calendar delete error:', err));
      }
    }
    
    // Clean up meeting data
    meetingSessions.delete(meetingId);
    
    const adminSession = adminSessions.get(session.adminId);
    if (adminSession) {
      adminSession.activeMeetings.delete(meetingId);
    }
    
    // Notify connected clients
    notifyAdmin(session.adminId, 'meeting_removed', { meetingId });
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Remove meeting error:', error);
    res.status(500).json({ error: 'Failed to remove meeting' });
  }
});

app.get('/meetings/list', (req, res) => {
  try {
    const { sessionId } = req.query;
    
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session expired' });
    }
    
    // Get all meetings for this admin
    const adminMeetings = Array.from(meetingSessions.values())
      .filter(meeting => meeting.adminId === session.adminId)
      .map(meeting => ({
        meetingId: meeting.meetingId,
        meetingCode: meeting.meetingCode,
        meetLink: meeting.meetLink,
        title: meeting.title,
        status: meeting.status,
        scheduledTime: meeting.scheduledTime,
        timeZone: meeting.timeZone,
        monitoring: meeting.monitoring,
        lifecycle: meeting.lifecycle,
        lastUpdated: meeting.lastUpdated
      }));
    
    res.json({ meetings: adminMeetings });
    
  } catch (error) {
    console.error('List meetings error:', error);
    res.status(500).json({ error: 'Failed to list meetings' });
  }
});

// WebSocket server for real-time updates
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, req) => {
  const clientId = generateId();
  activeConnections.set(clientId, { ws, adminId: null });
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'authenticate') {
        const session = sessions.get(data.sessionId);
        if (session) {
          const connection = activeConnections.get(clientId);
          connection.adminId = session.adminId;
          connection.sessionId = data.sessionId;
          
          // Send initial state
          const adminMeetings = Array.from(meetingSessions.values())
            .filter(meeting => meeting.adminId === session.adminId);
          
          ws.send(JSON.stringify({
            type: 'initial_state',
            meetings: adminMeetings
          }));
        }
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });
  
  ws.on('close', () => {
    activeConnections.delete(clientId);
  });
});

// Helper function to notify admin via WebSocket
function notifyAdmin(adminId, type, data) {
  activeConnections.forEach((connection, clientId) => {
    if (connection.adminId === adminId && connection.ws.readyState === WebSocket.OPEN) {
      connection.ws.send(JSON.stringify({
        type,
        data,
        timestamp: Date.now()
      }));
    }
  });
}

// Helper function to schedule reminder emails
function scheduleMeetingReminders(meetingId, scheduledTime, timeZone) {
  const meeting = meetingSessions.get(meetingId);
  if (!meeting) return;
  
  const scheduled = new Date(scheduledTime);
  const now = new Date();
  
  // Schedule 30-minute reminder
  const reminder30Min = scheduled.getTime() - 30 * 60000;
  if (reminder30Min > now.getTime()) {
    setTimeout(async () => {
      if (meetingSessions.has(meetingId)) {
        await sendEmailNotification(
          meeting.adminId,
          `Reminder: "${meeting.title}" starts in 30 minutes`,
          `Your meeting "${meeting.title}" is scheduled to start in 30 minutes.\n\nJoin: ${meeting.meetLink}\nTime: ${scheduled.toLocaleString()}`
        );
        meeting.remindersSent.push('30min');
        notifyAdmin(meeting.adminId, 'reminder_sent', { meetingId, reminder: '30min' });
      }
    }, reminder30Min - now.getTime());
  }
  
  // Schedule 10-minute reminder
  const reminder10Min = scheduled.getTime() - 10 * 60000;
  if (reminder10Min > now.getTime()) {
    setTimeout(async () => {
      if (meetingSessions.has(meetingId)) {
        await sendEmailNotification(
          meeting.adminId,
          `Reminder: "${meeting.title}" starts in 10 minutes`,
          `Your meeting "${meeting.title}" is about to start in 10 minutes.\n\nJoin: ${meeting.meetLink}\nTime: ${scheduled.toLocaleString()}`
        );
        meeting.remindersSent.push('10min');
        notifyAdmin(meeting.adminId, 'reminder_sent', { meetingId, reminder: '10min' });
      }
    }, reminder10Min - now.getTime());
  }
}

// Helper function to send email notifications
async function sendEmailNotification(adminId, subject, body) {
  try {
    const adminSession = adminSessions.get(adminId);
    if (!adminSession || !adminSession.oauth2Client) return;
    
    const gmail = google.gmail({ version: 'v1', auth: adminSession.oauth2Client });
    
    const emailLines = [
      'From: me',
      'To: me',
      'Content-Type: text/html; charset=utf-8',
      'MIME-Version: 1.0',
      `Subject: ${subject}`,
      '',
      body.replace(/\n/g, '<br>')
    ];
    
    const email = emailLines.join('\r\n').trim();
    const encodedEmail = Buffer.from(email).toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
    
    await gmail.users.messages.send({
      userId: 'me',
      requestBody: {
        raw: encodedEmail
      }
    });
    
    return true;
  } catch (error) {
    console.error('Email send error:', error);
    return false;
  }
}

// Helper function to simulate meeting health checks
function startMeetingHealthCheck(meetingId) {
  const interval = setInterval(() => {
    const meeting = meetingSessions.get(meetingId);
    if (!meeting || !meeting.monitoring) {
      clearInterval(interval);
      return;
    }
    
    // In real implementation, check actual meeting status via Google Meet API
    // For now, simulate status changes
    
    meeting.lastUpdated = Date.now();
    notifyAdmin(meeting.adminId, 'meeting_heartbeat', {
      meetingId,
      timestamp: meeting.lastUpdated
    });
    
  }, 30000); // Check every 30 seconds
}

// Session cleanup (garbage collection)
setInterval(() => {
  const now = Date.now();
  const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours
  
  // Clean up expired sessions
  sessions.forEach((session, sessionId) => {
    if (now - session.lastActive > 3600000) { // 1 hour inactivity
      sessions.delete(sessionId);
      
      const adminSession = adminSessions.get(session.adminId);
      if (adminSession && now - adminSession.createdAt > SESSION_TIMEOUT) {
        adminSession.activeMeetings.forEach(meetingId => {
          meetingSessions.delete(meetingId);
        });
        adminSessions.delete(session.adminId);
      }
    }
  });
  
  // Clean up stale meetings
  meetingSessions.forEach((meeting, meetingId) => {
    if (now - meeting.lastUpdated > 3600000 && !meeting.monitoring) { // 1 hour stale
      meetingSessions.delete(meetingId);
      
      const adminSession = adminSessions.get(meeting.adminId);
      if (adminSession) {
        adminSession.activeMeetings.delete(meetingId);
      }
    }
  });
  
}, 600000); // Run every 10 minutes

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    stats: {
      activeSessions: sessions.size,
      activeMeetings: meetingSessions.size,
      adminSessions: adminSessions.size,
      wsConnections: activeConnections.size
    }
  });
});

// Attach WebSocket server to HTTP server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  
  // Clear all in-memory data
  sessions.clear();
  adminSessions.clear();
  meetingSessions.clear();
  activeConnections.clear();
  
  wss.close();
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});