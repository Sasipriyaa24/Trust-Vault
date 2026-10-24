const app = require('./app');
const config = require('./config/env');

const server = app.listen(config.port, () => {
  console.log(`================================================================`);
  console.log(`🛡️  TrustVault Security Gateway running on port ${config.port}`);
  console.log(`🔒 Environment: ${config.nodeEnv}`);
  console.log(`🌐 Allowed Client Origin: ${config.clientOrigin}`);
  console.log(`⚡ Health Check: http://localhost:${config.port}/api/health`);
  console.log(`================================================================`);
});

// Graceful termination handling
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('TrustVault server closed.');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('TrustVault server closed.');
    process.exit(0);
  });
});
