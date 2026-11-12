#!/usr/bin/env python3
"""Check that the staged source still matches its reviewed SHA snapshot."""
from pathlib import Path
import hashlib
import json

repo = Path(__file__).resolve().parents[2]
manifest = json.loads((repo / 'integration/rdmetal/SNAPSHOT.json').read_text())
assert manifest['schema'] == 1
for entry in manifest['files']:
    relative = Path(entry['destination'])
    assert not relative.is_absolute() and '..' not in relative.parts
    path = repo / relative
    assert path.is_file() and not path.is_symlink(), relative
    data = path.read_bytes()
    assert len(data) == entry['bytes'], relative
    assert hashlib.sha256(data).hexdigest() == entry['sha256'], relative
print(f'RDMETAL_SOURCE_SNAPSHOT_OK files={len(manifest["files"])}')
