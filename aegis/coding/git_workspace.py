"""Ephemeral Git checkpoints for an already authorized in-memory snapshot.

This module never discovers, imports, or mutates a user's Git checkout. It does
not execute source code. Callers must use the Workspace context manager and
complete policy review before committing a proposed snapshot.
"""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import hashlib

from aegis import config
from aegis.coding.tools import validate_files
from aegis.control.store import digest


class WorkspaceError(ValueError):
    """A bounded Git workspace failed; messages never contain host paths."""


def _linked(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))


def configuration():
    requested = os.environ.get('AEGIS_GIT_WORKTREES') == '1'
    executable = shutil.which('git') if requested else None
    return {'requested': requested, 'enabled': bool(executable),
            'executable_hash': hashlib.sha256(Path(executable).read_bytes()).hexdigest() if executable else None,
            'scope': 'EPHEMERAL_REVIEWED_SNAPSHOT_ONLY', 'host_checkout_modified': False,
            'persistent_checkpoints': 'ENCRYPTED_TASK_SNAPSHOTS', 'physical_zeroization': False}


class Workspace:
    """A private repository plus detached worktree, deleted on context exit.

    stage(files) replaces the entire worktree snapshot and returns a diff from
    the original baseline. checkpoint() commits that snapshot and returns a
    checkpoint identifier. revert(identifier) accepts only identifiers issued
    by this instance. No branch names, commands, options, or paths are accepted
    from a model or end user.
    """

    def __init__(self, files):
        validate_files(files)
        self._git = shutil.which('git')
        if not self._git:
            raise WorkspaceError('Git is unavailable on this host')
        self._closed = False
        self._checkpoints = {}
        self._files = {}
        self._baseline = None
        parent = Path(config.WORKSPACES_DIR).absolute()
        for component in (parent, *parent.parents):
            if component.exists() and _linked(component):
                raise WorkspaceError('Git workspace storage must not use symlinks or junctions')
        self._parent = parent.resolve(strict=True)
        self._temporary = tempfile.TemporaryDirectory(prefix='aegis-git-', dir=self._parent)
        self._root = Path(self._temporary.name)
        # Prevent implicit garbage-collection deletion from bypassing the
        # explicit containment check in cleanup(). Context exit owns cleanup.
        self._temporary._finalizer.detach()
        try:
            self._repo = self._root / 'repository'
            self._tree = self._root / 'tree'
            self._home = self._root / 'home'
            self._hooks = self._root / 'empty-hooks'
            self._template = self._root / 'empty-template'
            for directory in (self._repo, self._home, self._hooks, self._template):
                directory.mkdir()
            self._empty = self._root / 'empty-config'
            self._empty.write_text('', encoding='utf-8')
            self._env = {key: value for key, value in os.environ.items()
                         if key.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR'}}
            self._env.update({'HOME': str(self._home), 'USERPROFILE': str(self._home),
                              'XDG_CONFIG_HOME': str(self._home), 'TMP': str(self._root), 'TEMP': str(self._root),
                              'TMPDIR': str(self._root), 'LANG': 'C', 'LC_ALL': 'C',
                              'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': str(self._empty),
                              'GIT_CONFIG_GLOBAL': str(self._empty), 'GIT_ATTR_NOSYSTEM': '1',
                              'GIT_TERMINAL_PROMPT': '0', 'GIT_LITERAL_PATHSPECS': '1',
                              'GIT_OPTIONAL_LOCKS': '0'})
            settings = {
                'core.hooksPath': str(self._hooks), 'protocol.allow': 'never', 'core.autocrlf': 'false',
                'core.attributesFile': str(self._empty), 'core.excludesFile': str(self._empty),
                'core.fsmonitor': 'false', 'core.untrackedCache': 'false', 'core.symlinks': 'false',
                'core.pager': 'cat', 'core.quotePath': 'true', 'core.logAllRefUpdates': 'false',
                'commit.gpgsign': 'false', 'tag.gpgsign': 'false', 'log.showSignature': 'false',
                'submodule.recurse': 'false', 'gc.auto': '0', 'maintenance.auto': 'false',
                'credential.helper': '', 'user.name': 'Aegis ephemeral workspace',
                'user.email': 'workspace@aegis.invalid', 'init.defaultObjectFormat': 'sha1',
            }
            self._prefix = [self._git, '--no-pager']
            for key, value in settings.items():
                self._prefix.extend(['-c', f'{key}={value}'])
            self._run(self._repo, 'init', '--initial-branch=aegis', '--template=' + str(self._template), '.')
            # Highest-precedence attributes disable all content transforms and
            # external diff/filter drivers from an imported .gitattributes file.
            (self._repo / '.git' / 'info' / 'attributes').parent.mkdir(exist_ok=True)
            (self._repo / '.git' / 'info' / 'attributes').write_text(
                '* -text -ident -filter -working-tree-encoding diff\n', encoding='utf-8')
            self._run(self._repo, 'commit', '--allow-empty', '--no-gpg-sign', '-m', 'Aegis workspace root')
            self._run(self._repo, 'worktree', 'add', '--detach', str(self._tree), 'HEAD')
            self._write(files)
            baseline = self.checkpoint()
            self._baseline = baseline['checkpoint']
        except Exception:
            self.cleanup()
            raise

    def _verify(self):
        if self._closed:
            raise WorkspaceError('Git workspace is closed')
        if (self._root.parent != self._parent or not self._root.name.startswith('aegis-git-')
                or _linked(self._parent) or _linked(self._root)
                or self._root.resolve(strict=True).parent != self._parent):
            raise WorkspaceError('Git workspace escaped its private storage directory')
        for base, directories, files in os.walk(self._root, followlinks=False):
            for name in directories + files:
                if _linked(Path(base) / name):
                    raise WorkspaceError('Symlinks and junctions are forbidden in Git workspaces')

    def _run(self, directory, *arguments):
        self._verify()
        if not directory.resolve(strict=True).is_relative_to(self._root):
            raise WorkspaceError('Git command escaped its workspace')
        try:
            result = subprocess.run(self._prefix + ['-C', str(directory), *arguments],
                                    env=self._env, stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=15, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            raise WorkspaceError('Isolated Git command failed or timed out') from None
        if result.returncode or len(result.stdout) > 2_500_000 or len(result.stderr) > 16_000:
            raise WorkspaceError('Isolated Git command failed or exceeded its output limit')
        return result.stdout.decode('utf-8', errors='strict')

    def _write(self, files):
        validate_files(files)
        self._verify()
        for name in self._files:
            if name not in files:
                path = self._tree / name
                if not path.resolve().is_relative_to(self._tree):
                    raise WorkspaceError('Snapshot path escaped its worktree')
                path.unlink()
        # Remove empty directories so a reviewed tree may replace a directory
        # with a file (or the reverse) without importing unrelated host files.
        for base, directories, _ in os.walk(self._tree, topdown=False):
            for directory in directories:
                path = Path(base) / directory
                if not any(path.iterdir()):
                    path.rmdir()
        for name, content in files.items():
            path = self._tree / name
            if not path.resolve().is_relative_to(self._tree):
                raise WorkspaceError('Snapshot path escaped its worktree')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode('utf-8'))
        actual = {path.relative_to(self._tree).as_posix() for path in self._tree.rglob('*')
                  if path.is_file() and path != self._tree / '.git'}
        if actual != set(files):
            raise WorkspaceError('Unrecognized files cannot enter a Git checkpoint')
        # Force-add only the fully bounded private snapshot; .gitignore cannot
        # silently exclude reviewed files from a checkpoint.
        self._run(self._tree, 'add', '--all', '--force', '--', '.')
        self._files = dict(files)

    def stage(self, files):
        """Stage an already reviewed/sanitized complete file map, without commit."""
        self._write(files)
        return self.diff()

    def checkpoint(self):
        self._run(self._tree, 'commit', '--allow-empty', '--no-gpg-sign', '-m', 'Aegis authorized snapshot')
        identity = self._run(self._tree, 'rev-parse', '--verify', 'HEAD').strip()
        if not re.fullmatch(r'[a-f0-9]{40}', identity):
            raise WorkspaceError('Git returned an invalid checkpoint identifier')
        self._checkpoints[identity] = dict(self._files)
        return {'checkpoint': identity, 'content_hash': digest(self._files), 'file_count': len(self._files)}

    def revert(self, checkpoint):
        self._verify()
        if not isinstance(checkpoint, str) or checkpoint not in self._checkpoints:
            raise WorkspaceError('Only checkpoints issued by this workspace can be restored')
        # Reset tracked state to an issued commit; no arbitrary Git revision or
        # pathspec is accepted. Every tree came from validate_files().
        self._run(self._tree, 'reset', '--hard', '--no-recurse-submodules', checkpoint, '--')
        self._files = dict(self._checkpoints[checkpoint])
        return self.diff()

    def diff(self):
        patch = self._run(self._tree, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                          '--full-index', '--no-color', self._baseline or 'HEAD', '--')
        return {'diff': patch, 'diff_hash': digest(patch), 'content_hash': digest(self._files),
                'file_count': len(self._files), 'host_checkout_modified': False}

    def cleanup(self):
        if self._closed:
            return
        self._verify()
        self._temporary.cleanup()
        self._closed = True

    def __enter__(self):
        self._verify()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.cleanup()
