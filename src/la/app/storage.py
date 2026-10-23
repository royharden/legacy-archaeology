"""Bounded local storage primitives; no decision journal or service.

Atomic publication uses a same-directory fsynced stage and exclusive hard link.
Current cache replacement uses a fsynced stage and atomic replace under a lock.
Orphan stages never count as commits and are retained for explicit recovery.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from la.contracts import canonical, digest, sha256

SOURCE_BYTES = 5*1024*1024
JSON_BYTES = 16*1024*1024
MEMBER_BYTES = 32*1024*1024
POINTER_BYTES = 4096
_held = ContextVar('la_owned_file_locks', default=frozenset())
UNSET = object()


def contained(root, value, *, exists=False):
    root = Path(root).resolve()
    path = (root/value).resolve()
    if not path.is_relative_to(root): raise ValueError('path escapes declared root')
    if exists and not path.exists(): raise ValueError('path does not exist')
    return path


def bounded_bytes(path, *, limit=MEMBER_BYTES):
    path = Path(path)
    if type(limit) is not int or not 0 <= limit <= MEMBER_BYTES:
        raise ValueError('invalid bounded read limit')
    if path.is_symlink(): raise ValueError('artifact symlink refused')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('artifact is not a bounded regular file')
        data = handle.read(limit+1)
        after = os.fstat(handle.fileno())
    if len(data) > limit or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('artifact changed during bounded read')
    return data


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise ValueError('duplicate JSON member')
        value[key] = item
    return value


def bounded_json(path, *, limit=JSON_BYTES, canonical_required=False):
    data = bounded_bytes(path, limit=limit)
    def invalid_constant(value): raise ValueError('nonfinite JSON number')
    try:
        value = json.loads(data, object_pairs_hook=_object, parse_constant=invalid_constant)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('invalid or excessively nested JSON') from None
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 32: raise ValueError('JSON nesting exceeds32')
        if isinstance(item, dict): stack.extend((child, depth+1) for child in item.values())
        elif isinstance(item, list): stack.extend((child, depth+1) for child in item)
    if canonical_required and data != canonical(value)+b'\n':
        raise ValueError('noncanonical committed artifact')
    return value


def observe_source(path):
    """One bounded-memory pass; complete stream hash/count, never a prefix hash.

    Oversize bytes are not retained. An unstable file is observation-only and
    must be sent to a producer refusal, never accepted from buffered bytes.
    """
    path=Path(path)
    if path.is_symlink(): raise ValueError('source symlink refused')
    hasher=hashlib.sha256(); buffered=bytearray(); size=0; lines=0; last=None
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
    with os.fdopen(os.open(path,flags),'rb') as handle:
        before=os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode): raise ValueError('source must be a regular file')
        while True:
            chunk=handle.read(64*1024)
            if not chunk: break
            hasher.update(chunk); size+=len(chunk); lines+=chunk.count(b'\n'); last=chunk[-1]
            if size<=SOURCE_BYTES: buffered.extend(chunk)
            else: buffered.clear()
        after=os.fstat(handle.fileno())
    try: current=path.stat()
    except OSError: current=None
    def stamp(info):
        return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns) if info else None
    stable=stamp(before)==stamp(after)==stamp(current) and size==after.st_size
    observation=dict(schema_version=1,kind='complete_source_stream_observation',
        source_sha256=hasher.hexdigest(),input_byte_count=size,
        observed_count=lines+(1 if size and last!=10 else 0),
        terminal_newline=bool(size and last==10),stable=stable,
        complete_stream=True,retained=size<=SOURCE_BYTES and stable,
        memory_limit_bytes=SOURCE_BYTES,chunk_bytes=64*1024,
        before_identity_sha256=digest(stamp(before)),after_identity_sha256=digest(stamp(current)),
        reader_policy_sha256=digest({'version':1,'chunk_bytes':64*1024,'memory_limit_bytes':SOURCE_BYTES,'complete_stream_hash':True}))
    observation['observation_sha256']=digest(observation)
    return (bytes(buffered) if observation['retained'] else None),observation


def _sync_parent(path):
    # Windows has no portable stdlib directory fsync; file fsync and atomic
    # publication are used, without claiming power-loss durability there.
    if os.name == 'posix':
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try: os.fsync(descriptor)
        finally: os.close(descriptor)


def _stage(path, data, limit):
    path = Path(path)
    if type(data) is not bytes or type(limit) is not int or not 0 <= limit <= MEMBER_BYTES:
        raise ValueError('invalid publication payload/limit')
    if len(data) > limit: raise ValueError('artifact publication byte limit')
    path.parent.mkdir(parents=True, exist_ok=True)
    stage = path.with_name('.'+path.name+'.la-tmp-'+uuid.uuid4().hex)
    with stage.open('xb') as handle:
        handle.write(data); handle.flush(); os.fsync(handle.fileno())
    return stage


def publish_bytes(path, data, *, limit=MEMBER_BYTES):
    """Exclusive final publication. Exact retry succeeds; frozen collision fails."""
    path = Path(path)
    if path.is_symlink(): raise ValueError('immutable artifact symlink refused')
    if path.exists():
        if bounded_bytes(path, limit=limit) != data: raise ValueError('immutable artifact collision')
        return
    stage = _stage(path, data, limit)
    try:
        try:
            os.link(stage, path)
            _sync_parent(path.parent)
        except FileExistsError:
            if bounded_bytes(path, limit=limit) != data: raise ValueError('immutable artifact collision')
    finally:
        # Only this invocation's exact newly created temp is removed. Crash
        # orphans are ignored, never discovered and deleted by a broad sweep.
        stage.unlink(missing_ok=True)


@contextmanager
def file_lock(path):
    """Nonwaiting process lock; process death releases the OS lock automatically."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink(): raise ValueError('lock symlink refused')
    key = str(path.resolve())
    if key in _held.get():
        yield
        return
    with path.open('a+b') as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0: handle.write(b'0'); handle.flush(); os.fsync(handle.fileno())
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            elif os.name == 'posix':
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else: raise ValueError('unsupported platform locking')
        except (OSError, BlockingIOError):
            raise ValueError('run/artifact busy; retry explicitly after its owner finishes') from None
        token = _held.set(_held.get() | {key})
        try: yield
        finally:
            _held.reset(token)
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else: fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_lock(root, run):
    # Filename is a hash of the declared logical key, never a path supplied by
    # an input file. The lock is concurrency control, not a decision authority.
    return file_lock(contained(root, '.locks/'+digest(run)+'.lock'))


def pointer_token(path):
    path = Path(path)
    if not path.exists(): return None
    try: return digest(bounded_json(path, limit=POINTER_BYTES, canonical_required=True))
    except ValueError:
        return 'raw:'+sha256(bounded_bytes(path,limit=POINTER_BYTES))


def replace_pointer(path, value, *, expected=UNSET):
    path = Path(path)
    data = canonical(value)+b'\n'
    if len(data) > POINTER_BYTES: raise ValueError('pointer byte limit')
    with file_lock(path.with_name('.'+path.name+'.lock')):
        exists=path.exists()
        try: current = bounded_json(path, limit=POINTER_BYTES, canonical_required=True) if exists else None
        except ValueError: current=UNSET
        if current == value: return  # Exact retry has no second effect.
        actual = pointer_token(path)
        if expected is UNSET and exists or expected is not UNSET and expected != actual:
            raise ValueError('content-bound pointer CAS failed')
        stage = _stage(path, data, POINTER_BYTES)
        try:
            if path.is_symlink(): raise ValueError('pointer symlink refused')
            os.replace(stage, path)
            _sync_parent(path.parent)
        finally: stage.unlink(missing_ok=True)


def stage_inventory(root, *, maximum=128):
    """Bounded own-directory diagnostics, never cleanup or authority recovery."""
    root = Path(root).resolve()
    result = []
    for index, path in enumerate(root.iterdir()):
        if index >= 1024: raise ValueError('storage inventory entry limit')
        if '.la-tmp-' not in path.name or not path.name.startswith('.'): continue
        if path.is_symlink(): raise ValueError('orphan stage symlink refused')
        if len(result) >= maximum: raise ValueError('orphan stage inventory limit')
        info = path.stat()
        result.append(dict(name=path.name, bytes=info.st_size, committed=False))
    return sorted(result, key=lambda item:item['name'])


def atomic_directory(stage, destination):
    """Publish only a caller-created same-parent staging directory, never overwrite."""
    stage, destination = Path(stage), Path(destination)
    parent = destination.parent.resolve()
    if (stage.is_symlink() or destination.is_symlink() or stage.parent.resolve() != parent
            or not (stage.name.startswith('.'+destination.name+'.la-tmp-') or stage.name.startswith('.bundle-stage.la-tmp-'))):
        raise ValueError('directory publication outside owned stage')
    with file_lock(destination.with_name('.'+destination.name+'.publish.lock')):
        if destination.exists(): raise ValueError('immutable directory already published; verify exact retry')
        _sync_parent(stage)
        os.rename(stage, destination)
        _sync_parent(parent)
