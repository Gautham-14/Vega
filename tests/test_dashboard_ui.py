"""The website is a read-only client and plots actual timestamped measurements."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_only_has_auth_mutations_and_no_fake_telemetry():
    html = (ROOT / 'frontend/index.html').read_text(encoding='utf-8')
    app = (ROOT / 'frontend/js/app.js').read_text(encoding='utf-8')
    chart = (ROOT / 'frontend/js/telemetry.js').read_text(encoding='utf-8')
    assert '/static/js/control.js' not in html and '/static/js/coding.js' not in html
    assert 'localStorage' not in app and 'sessionStorage' not in app
    assert app.count("method:'POST'") == 2
    assert '/api/auth/login' in app and '/api/auth/logout' in app
    assert 'Math.random' not in chart and 'Math.sin' not in chart
    assert 'HOST_MEASURED' in chart
    assert 'HOSTED_PREVIEW' in app


def test_chart_uses_elapsed_time_and_handles_missing_values():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node optional for frontend checks')
    script = f"""
const assert = require('node:assert/strict');
const t = require({json.dumps(str(ROOT / 'frontend/js/telemetry.js'))});
assert.equal(t.points([], 'cpu_percent'), '');
assert.equal(t.percent(null), 'Unavailable');
const rows = [{{timestamp:100,cpu_percent:0}},{{timestamp:110,cpu_percent:50}},{{timestamp:140,cpu_percent:100}}];
assert.equal(t.points(rows, 'cpu_percent'), '0.0,179.0 180.0,90.0 720.0,1.0');
assert.equal(t.points([{{timestamp:100,cpu_percent:null}}], 'cpu_percent'), '');
"""
    subprocess.run([node, '-e', script], check=True, capture_output=True, text=True)
