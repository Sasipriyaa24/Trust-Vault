const { spawn } = require('child_process');
const path = require('path');

const rootDir = __dirname;
const isWindows = process.platform === 'win32';
const npmCmd = isWindows ? 'npm.cmd' : 'npm';

console.log('================================================================');
console.log('🛡️  Starting TrustVault Full-Stack Platform...');
console.log('   - Backend API Gateway: http://localhost:5000');
console.log('   - Frontend Client:     http://localhost:5173');
console.log('================================================================\n');

// 1. Start Server Process
const serverProc = spawn(npmCmd, ['run', 'dev'], {
  cwd: path.join(rootDir, 'server'),
  stdio: 'inherit',
  shell: true
});

// 2. Start Client Process
const clientProc = spawn(npmCmd, ['run', 'dev'], {
  cwd: path.join(rootDir, 'client'),
  stdio: 'inherit',
  shell: true
});

function cleanup() {
  console.log('\nShutting down TrustVault full-stack services...');
  serverProc.kill();
  clientProc.kill();
  process.exit(0);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

serverProc.on('exit', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`Backend server exited with code ${code}`);
  }
});

clientProc.on('exit', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`Frontend client exited with code ${code}`);
  }
});
