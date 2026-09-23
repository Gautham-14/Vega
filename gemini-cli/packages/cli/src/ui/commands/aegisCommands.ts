import { CommandKind, type SlashCommand } from './types.js';
import { setPersona, aegisFetch, currentPersona } from '../../utils/aegisApi.js';

export const personaCommand: SlashCommand = {
  name: 'persona',
  description: 'Switch Aegis Actor Persona (e.g., Operator, Data Owner, Security Officer)',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    if (!args) {
      return { type: 'message', messageType: 'info', content: `Current Persona: ${currentPersona}` };
    }
    setPersona(args.trim());
    return { type: 'message', messageType: 'info', content: `Switched Persona to: ${currentPersona}` };
  },
};

export const importCommand: SlashCommand = {
  name: 'import',
  description: 'Data Owner: Import a repository (e.g., /import ./my-code)',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    if (!args) return { type: 'message', messageType: 'error', content: 'Please provide a path.' };
    try {
      const data = await aegisFetch('/coding/repositories', {
        method: 'POST',
        body: JSON.stringify({ name: 'imported-repo', path: args.trim() }),
      });
      return { type: 'message', messageType: 'info', content: `Repository imported: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const registerCommand: SlashCommand = {
  name: 'register',
  description: 'Operator: Register a new capsule (e.g., reference or ollama)',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    try {
      const provider = args ? args.trim() : 'reference';
      const data = await aegisFetch('/coding/capsules', {
        method: 'POST',
        body: JSON.stringify({ provider }),
      });
      return { type: 'message', messageType: 'info', content: `Capsule registered: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const approveCommand: SlashCommand = {
  name: 'approve',
  description: 'Reviewer: Approve or reject an approval ID',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    const [id, decision] = (args || '').split(' ');
    if (!id || !decision) return { type: 'message', messageType: 'error', content: 'Usage: /approve <id> <approve|reject>' };
    try {
      const data = await aegisFetch(`/control/approvals/${id}/decide`, {
        method: 'POST',
        body: JSON.stringify({ decision: decision.toUpperCase() }),
      });
      return { type: 'message', messageType: 'info', content: `Decision recorded: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const activateCommand: SlashCommand = {
  name: 'activate',
  description: 'Model Custodian: Activate a capsule',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    const id = (args || '').trim();
    if (!id) return { type: 'message', messageType: 'error', content: 'Usage: /activate <capsule_id>' };
    try {
      const data = await aegisFetch(`/control/capsules/${id}/approve`, {
        method: 'POST',
      });
      return { type: 'message', messageType: 'info', content: `Capsule activated: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const leaseCommand: SlashCommand = {
  name: 'lease',
  description: 'Data Owner: Create a lease',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    const [repository, capsule, recipient, mode] = (args || '').split(' ');
    if (!repository || !capsule || !recipient || !mode) {
      return { type: 'message', messageType: 'error', content: 'Usage: /lease <repo_id> <capsule_id> <recipient> <mode>' };
    }
    try {
      const data = await aegisFetch('/coding/leases', {
        method: 'POST',
        body: JSON.stringify({ repository, capsule, recipient, mode, duration_minutes: 15, allow_export: true }),
      });
      return { type: 'message', messageType: 'info', content: `Lease created: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const applyCommand: SlashCommand = {
  name: 'apply',
  description: 'Task Owner: Apply a diff hash',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    const [taskId, hash] = (args || '').split(' ');
    if (!taskId || !hash) return { type: 'message', messageType: 'error', content: 'Usage: /apply <task_id> <diff_hash>' };
    try {
      const data = await aegisFetch(`/coding/tasks/${taskId}/apply`, {
        method: 'POST',
        body: JSON.stringify({ diff_hash: hash }),
      });
      return { type: 'message', messageType: 'info', content: `Diff applied: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const exportCommand: SlashCommand = {
  name: 'export',
  description: 'Task Owner: Request export for a task',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    const id = (args || '').trim();
    if (!id) return { type: 'message', messageType: 'error', content: 'Usage: /export <task_id>' };
    try {
      const data = await aegisFetch(`/coding/tasks/${id}/export-request`, {
        method: 'POST',
      });
      return { type: 'message', messageType: 'info', content: `Export requested: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const closeCommand: SlashCommand = {
  name: 'close',
  description: 'Task Owner: Close a task',
  kind: CommandKind.BUILT_IN,
  autoExecute: false,
  action: async (context, args) => {
    const id = (args || '').trim();
    if (!id) return { type: 'message', messageType: 'error', content: 'Usage: /close <task_id>' };
    try {
      const data = await aegisFetch(`/coding/tasks/${id}/close`, {
        method: 'POST',
      });
      return { type: 'message', messageType: 'info', content: `Task closed: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const validateCommand: SlashCommand = {
  name: 'validate',
  description: 'Run Aegis Validation',
  kind: CommandKind.BUILT_IN,
  autoExecute: true,
  action: async (context, args) => {
    try {
      context.ui.setDebugMessage('Running Aegis Validation...');
      const data = await aegisFetch('/coding/validation', {
        method: 'POST',
      });
      return { type: 'message', messageType: 'info', content: `Validation results: ${JSON.stringify(data, null, 2)}` };
    } catch (e: any) {
      return { type: 'message', messageType: 'error', content: e.message };
    }
  },
};

export const aegisCommands = [
  personaCommand,
  importCommand,
  registerCommand,
  approveCommand,
  activateCommand,
  leaseCommand,
  applyCommand,
  exportCommand,
  closeCommand,
  validateCommand,
];
