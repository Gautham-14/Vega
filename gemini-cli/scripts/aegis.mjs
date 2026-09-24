#!/usr/bin/env node
// Repository-local Aegis entrypoint. The upstream cloud agent is not started.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../../aegis_cli.py', import.meta.url));
if (!existsSync(script)) {
  console.error('Aegis requires its full local runtime checkout. Run this launcher from the Aegis repository.');
  process.exit(1);
}
const child = spawn(process.env.AEGIS_PYTHON || 'python', [script, ...process.argv.slice(2)], {
  stdio: 'inherit', shell: false, windowsHide: true,
});
child.once('error', () => {
  console.error('Cannot start Python. Install Python 3.11+ or set AEGIS_PYTHON to its executable path.');
  process.exitCode = 1;
});
child.once('exit', (code, signal) => { process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 1); });
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => { if (!child.killed) child.kill(signal); });
}
