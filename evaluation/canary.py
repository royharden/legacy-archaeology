"""Future explicitly approved CANARY collector SOURCE; never invoked on import.

No accounts/ACLs, identity switching, subprocesses, services or hidden assets.
Only an external evaluator witness may attest the resulting observation. This
collector has no signing key and cannot establish handle/network/broker isolation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import socket

from .artifacts import digest, is_sha
from .eligibility import ReceiptVerifier, closed, hashes, text

REQUEST_KEYS = {'schema_version', 'kind', 'edition', 'freeze_sha256', 'nonce',
                'expected_identity', 'expected_host', 'source_sha256', 'config_sha256',
                'source_path', 'config_path', 'canary_file', 'canary_directory',
                'relative_file', 'cwd', 'collector_sha256'}


class CanaryProbeFailure(ValueError):
    def __init__(self, observation: dict):
        super().__init__('canary accessible/missing/unsupported: custody remains unverified')
        self.observation = observation  # Failures survive without any contents/listings.


def observed_identity() -> str:
    """Actual OS principal; environment username variables are not evidence."""
    system = platform.system()
    if system == 'Linux' and hasattr(os, 'geteuid'):
        return 'linux:uid=' + str(os.geteuid()) + ':gid=' + str(os.getegid())
    if system != 'Windows':
        raise ValueError('unsupported identity platform')
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    token = wintypes.HANDLE()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), 'identity token unavailable')
    try:
        needed = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not 1 <= needed.value <= 65536:
            raise ValueError('unsupported token observation size')
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), 'identity token unavailable')
        class SidAndAttributes(ctypes.Structure):
            _fields_ = [('sid', ctypes.c_void_p), ('attributes', wintypes.DWORD)]
        sid = ctypes.cast(buffer, ctypes.POINTER(SidAndAttributes)).contents.sid
        rendered = wintypes.LPWSTR()
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(rendered)):
            raise OSError(ctypes.get_last_error(), 'identity SID unavailable')
        try:
            return 'windows:sid=' + rendered.value
        finally:
            kernel.LocalFree(ctypes.cast(rendered, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)


def _bounded_pin(path: str) -> str:
    supplied = Path(path)
    if supplied.is_symlink() or not supplied.is_file() or supplied.stat().st_size > 1024 * 1024:
        raise ValueError('approved public source/config artifact unavailable or oversized')
    with supplied.open('rb') as handle:
        content = handle.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ValueError('approved identity artifact exceeded bound')
    return hashlib.sha256(content).hexdigest()


def _probe(operation: str, path: str) -> dict:
    try:
        if operation == 'directory_list':
            # Opening the iterator itself must be denied. Never retain names or
            # contents, even if the canary directory unexpectedly becomes visible.
            with os.scandir(path) as iterator:
                next(iterator, None)
        else:
            descriptor = os.open(path, os.O_RDONLY)
            os.close(descriptor)  # Never read canary bytes.
        return {'operation': operation, 'result': 'accessible', 'errno': None,
                'winerror': None, 'exception_type': None}
    except PermissionError as exc:
        return {'operation': operation, 'result': 'denied', 'errno': exc.errno,
                'winerror': getattr(exc, 'winerror', None), 'exception_type': 'PermissionError'}
    except OSError as exc:
        return {'operation': operation, 'result': 'error', 'errno': exc.errno,
                'winerror': getattr(exc, 'winerror', None), 'exception_type': type(exc).__name__}


def collect_canary(request: dict, *, authority_receipt: dict, verifier: ReceiptVerifier) -> dict:
    """Execute only later under explicitly authorized inference identity.

    Evaluator must separately establish that the canary file/directory exists and
    is evaluator-owned. Missing paths are errors, not denied-access proof. A
    trusted external witness validates the process/nonce and signs this output;
    untrusted JSON or this collector's own narrative is never sufficient.
    """
    item = closed(request, REQUEST_KEYS, 'canary request')
    if item['kind'] != 'approved_canary_probe':
        raise ValueError('only approved CANARY paths may be probed')
    hashes(item, ('freeze_sha256', 'nonce', 'source_sha256', 'config_sha256', 'collector_sha256'))
    text(item['edition'], 'edition')
    grant = closed(verifier.verify(authority_receipt, 'run_owner'),
                   {'schema_version', 'action', 'request_sha256'}, 'canary authority')
    if grant['action'] != 'collect_canary' or grant['request_sha256'] != digest(item):
        raise ValueError('no exact approved canary request')
    if platform.system() not in ('Windows', 'Linux'):
        raise ValueError('unsupported probe platform; custody remains unverified')
    # Never change cwd, impersonate, spawn or modify permissions.
    cwd = os.path.normcase(os.path.abspath(item['cwd']))
    file_path = os.path.normcase(os.path.abspath(item['canary_file']))
    directory = os.path.normcase(os.path.abspath(item['canary_directory']))
    if os.path.normcase(os.getcwd()) != cwd or os.path.isabs(item['relative_file']):
        raise ValueError('relative probe must use the observed current directory')
    if os.path.normcase(os.path.abspath(os.path.join(cwd, item['relative_file']))) != file_path:
        raise ValueError('relative and absolute probes must name the exact same canary')
    if os.path.commonpath([file_path, directory]) != directory or file_path == directory:
        raise ValueError('canary file must be inside the approved canary directory')
    collector_pin = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    identity, host = observed_identity(), socket.gethostname()
    source_pin, config_pin = _bounded_pin(item['source_path']), _bounded_pin(item['config_path'])
    if (identity != item['expected_identity'] or host != item['expected_host']
            or source_pin != item['source_sha256'] or config_pin != item['config_sha256']
            or collector_pin != item['collector_sha256']):
        raise ValueError('actual identity/host/collector/source/config differs from approved subject')
    results = [_probe('absolute_open', file_path), _probe('relative_open', item['relative_file']),
               _probe('directory_list', directory)]
    observation = {'schema_version': 1, 'kind': 'observed_canary_probe', 'edition': item['edition'],
        'freeze_sha256': item['freeze_sha256'], 'nonce': item['nonce'], 'identity': identity, 'host': host,
        'collector_sha256': collector_pin, 'observed_source_sha256': source_pin,
        'observed_config_sha256': config_pin, 'canary_file_sha256': digest(file_path),
        'canary_directory_sha256': digest(directory), 'observed_at': datetime.now(timezone.utc).isoformat(),
        'probes': results}
    # Accessible/error observations are retained and rejected by custody validation.
    # Return no file bytes, names/listings, source/config contents or signing key.
    sealed = {**observation, 'observation_sha256': digest(observation)}
    if any(result['result'] != 'denied' or (result['errno'] not in (1, 13) and result['winerror'] != 5)
           for result in results):
        raise CanaryProbeFailure(sealed)
    return sealed
