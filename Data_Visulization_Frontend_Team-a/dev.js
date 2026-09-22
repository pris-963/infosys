import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('======================================================================');
console.log('STARTING SECURITY OPERATIONS DASHBOARD (INTEGRATED FULL-STACK)');
console.log('======================================================================');

const pythonAppPath = path.resolve(__dirname, '..', 'Data_Visulization_Backend_Team-a', 'backend', 'app.py');
let backend;

if (fs.existsSync(pythonAppPath)) {
  console.log(`Booting Flask Python backend (${pythonAppPath})...`);
  backend = spawn('python', [pythonAppPath], {
    cwd: path.dirname(pythonAppPath),
    stdio: 'inherit',
    shell: true
  });
} else {
  console.log('Booting fallback Node API server (server.js)...');
  backend = spawn('node', ['server.js'], { stdio: 'inherit', shell: true });
}

console.log('Booting Vite development server (port 3000)...');
const frontend = spawn('npx', ['vite', '--port=3000', '--host=0.0.0.0'], { stdio: 'inherit', shell: true });

process.on('SIGINT', () => {
  backend.kill();
  frontend.kill();
  process.exit();
});

process.on('exit', () => {
  backend.kill();
  frontend.kill();
});

