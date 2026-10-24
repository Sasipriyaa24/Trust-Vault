const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('./config/env');

// Import routes
const authRoutes = require('./routes/authRoutes');
const documentRoutes = require('./routes/documentRoutes');
const permissionRoutes = require('./routes/permissionRoutes');
const adminRoutes = require('./routes/adminRoutes');
const categoryRoutes = require('./routes/categoryRoutes');

const app = express();

// 1. HTTP Security Headers via Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", "*"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    frameguard: { action: 'deny' },
    noSniff: true,
  })
);

const crypto = require('crypto');

// 2. Strict CORS Policy
const allowedOrigins = [
  config.clientOrigin,
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:5174'
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl, or supertest)
      if (!origin || allowedOrigins.includes(origin) || config.clientOrigin === '*') {
        return callback(null, true);
      }
      return callback(new Error('CORS policy: Access Denied for this origin.'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID'],
    exposedHeaders: ['X-Request-ID']
  })
);

// 2.1 Request Correlation ID Middleware (Distributed Audit Tracing)
app.use((req, res, next) => {
  const incomingId = req.headers['x-request-id'];
  // Sanitize incoming request ID to prevent injection / oversized values
  const safeId = (typeof incomingId === 'string' && /^[a-zA-Z0-9_\-]{8,64}$/.test(incomingId))
    ? incomingId
    : `req-${crypto.randomUUID()}`;
  req.id = safeId;
  res.setHeader('X-Request-ID', safeId);
  next();
});

// 3. Rate Limiting (Defense against DoS and Brute Force)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'test' ? 10000 : 300, // relaxed in automated tests
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests from this IP address. Please try again after 15 minutes.',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});
app.use('/api/', globalLimiter);

// 4. Request Body Parsers
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 5. Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'TrustVault Enterprise Security Gateway',
    timestamp: new Date().toISOString(),
    environment: config.nodeEnv
  });
});

// 6. Mount API Routers
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/documents/:id/permissions', permissionRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/categories', categoryRoutes);

const path = require('path');
const fs = require('fs');

// 6.5 Production Static Serving (Single-service deployment mode)
const clientDistPath = path.resolve(__dirname, '../../client/dist');
if (fs.existsSync(clientDistPath)) {
  app.use(express.static(clientDistPath));
  app.use((req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    res.sendFile(path.join(clientDistPath, 'index.html'));
  });
}

// 7. 404 Route Handler
app.use((req, res) => {
  res.status(404).json({
    error: `Endpoint not found: ${req.method} ${req.originalUrl}`,
    code: 'NOT_FOUND'
  });
});

// 8. Fail-Closed Global Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled Application Error:', err);

  // Return sanitised error without internal stack trace
  res.status(err.status || 500).json({
    error: 'A server error occurred. Request failed closed for security.',
    code: err.code || 'INTERNAL_SERVER_ERROR',
    ...(config.nodeEnv === 'development' && { details: err.message })
  });
});

module.exports = app;
