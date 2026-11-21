"""Small JSON storage layer: accounts, sessions, and one private file per user."""

from datetime import date, datetime
from pathlib import Path
import hashlib
import json
import math
import os
import re
import secrets
import tempfile
import time
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from filelock import FileLock


DATA_DIR = Path(os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', '.'))
PRIVATE_DIR = DATA_DIR / 'studyflow_private'
SESSION_SECONDS = 7 * 24 * 60 * 60
PASSWORD_HASHER = PasswordHasher()  # Argon2id includes a new random salt for each password.
# Unknown usernames still perform a password check, reducing timing differences.
DUMMY_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(32))


class AuthenticationError(ValueError):
    pass


class RateLimitError(ValueError):
    pass


class ConflictError(ValueError):
    pass


def read_json(path, default):
    # Only a missing file gets a default. Never silently overwrite corrupt data.
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return default


def atomic_write_json(path, data):
    """Caller holds the file lock for the entire read/change/write operation."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         dir=path.parent, suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # Persist the directory entry too on Railway's Linux volume.
        if os.name != 'nt':
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def auth_path():
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    return PRIVATE_DIR / 'accounts.json'


def read_accounts():
    return read_json(auth_path(), {'users': {}, 'sessions': {}, 'attempts': {}})


def token_key(token):
    # Only the browser holds the original login token; JSON stores its hash.
    return hashlib.sha256(token.encode()).hexdigest()


def session_user(accounts, token):
    session = accounts['sessions'].get(token_key(token or ''))
    if not session or session['expires'] <= time.time():
        raise AuthenticationError('Please log in again.')
    return session['user_id']


def current_user(token):
    with FileLock(str(auth_path()) + '.lock', timeout=10):
        try:
            return session_user(read_accounts(), token)
        except AuthenticationError:
            return None


def new_user_data():
    return {'revision': 0, 'subjects': [],
            'settings': {'daily_hours': 3, 'study_minutes': 25, 'break_minutes': 5},
            'sessions': {'date': date.today().isoformat(), 'completed': 0},
            'timer': {'remaining': 1500, 'total': 1500, 'running': False,
                      'mode': 'Study', 'deadline': None}}


def user_path(user_id):
    # IDs come from our session registry, never a URL, username, or form field.
    if not re.fullmatch(r'[0-9a-f]{32}', user_id):
        raise AuthenticationError('Invalid account.')
    return PRIVATE_DIR / 'users' / f'{user_id}.json'


def authenticate(username, password, address, signup=False):
    username = str(username).strip().casefold()
    password = str(password)
    path = auth_path()
    with FileLock(str(path) + '.lock', timeout=10):
        accounts = read_accounts()
        now = time.time()
        attempts = {k: v for k, v in accounts['attempts'].items() if v['until'] > now}
        keys = [('ip:' + token_key(address), 20), ('user:' + token_key(username), 5)]
        if any(attempts.get(key, {}).get('count', 0) >= limit for key, limit in keys):
            raise RateLimitError('Too many attempts. Try again in 15 minutes.')
        for key, _ in keys:
            entry = attempts.setdefault(key, {'count': 0, 'until': now + 900})
            entry['count'] += 1
        accounts['attempts'] = attempts
        # Persist attempts before doing expensive password work (also survives restarts).
        atomic_write_json(path, accounts)
        if not re.fullmatch(r'[a-z0-9_]{3,40}', username) or not 12 <= len(password) <= 128:
            raise ValueError('Use a 3–40 character username (letters, digits, underscores) '
                             'and a password of 12–128 characters.')
        user = accounts['users'].get(username)
        if signup:
            if user:
                raise ValueError('Unable to create an account with those details.')
            user = {'id': uuid.uuid4().hex, 'password_hash': PASSWORD_HASHER.hash(password)}
            atomic_write_json(user_path(user['id']), new_user_data())
            accounts['users'][username] = user
        else:
            try:
                PASSWORD_HASHER.verify(user['password_hash'] if user else DUMMY_HASH, password)
            except (VerificationError, InvalidHashError):
                raise AuthenticationError('Invalid username or password.') from None
            if not user:
                raise AuthenticationError('Invalid username or password.')
            if PASSWORD_HASHER.check_needs_rehash(user['password_hash']):
                user['password_hash'] = PASSWORD_HASHER.hash(password)
        token = secrets.token_urlsafe(32)
        accounts['sessions'] = {k: v for k, v in accounts['sessions'].items() if v['expires'] > now}
        accounts['sessions'][token_key(token)] = {'user_id': user['id'], 'expires': now + SESSION_SECONDS}
        accounts['attempts'].pop(keys[1][0], None)
        atomic_write_json(path, accounts)
        return token


def logout(token):
    path = auth_path()
    with FileLock(str(path) + '.lock', timeout=10):
        accounts = read_accounts()
        accounts['sessions'].pop(token_key(token or ''), None)
        atomic_write_json(path, accounts)


def valid_number(value, minimum, maximum, whole=False):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError('Enter a valid number.')
    if not math.isfinite(value) or not minimum <= value <= maximum or (whole and value != int(value)):
        raise ValueError(f'Enter a number between {minimum:g} and {maximum:g}.')
    return value


def validate_subjects(subjects):
    if not isinstance(subjects, list) or len(subjects) > 200:
        raise ValueError('You can save up to 200 subjects.')
    for subject in subjects:
        if not isinstance(subject['name'], str) or not 1 <= len(subject['name'].strip()) <= 120:
            raise ValueError('Subject names must contain 1–120 characters.')
        date.fromisoformat(subject['exam_date'])
        if subject['difficulty'] not in ('Easy', 'Medium', 'Hard'):
            raise ValueError('Choose a valid difficulty.')
        if not re.fullmatch(r'#[0-9a-fA-F]{6}', subject['color']):
            raise ValueError('Choose a valid six-digit hex color.')
        if not isinstance(subject['chapters'], list) or len(subject['chapters']) > 500:
            raise ValueError('You can save up to 500 chapters per subject.')
        for chapter in subject['chapters']:
            if not isinstance(chapter['name'], str) or not 1 <= len(chapter['name'].strip()) <= 120:
                raise ValueError('Chapter names must contain 1–120 characters.')
            valid_number(chapter['hours'], 0.001, 10000)
            if not isinstance(chapter['completed'], bool):
                raise ValueError('Invalid chapter progress.')


def settle_timer(data):
    """Finish a saved timer once, even when two devices check it together."""
    timer = data['timer']
    if not timer['running'] or timer['deadline'] > time.time():
        return False
    if timer['mode'] == 'Study':
        completed_date = datetime.fromtimestamp(timer['deadline']).date().isoformat()
        sessions = data['sessions']
        if sessions['date'] != completed_date:
            sessions.update(date=completed_date, completed=0)
        sessions['completed'] += 1
    timer['mode'] = 'Break' if timer['mode'] == 'Study' else 'Study'
    minutes = data['settings']['break_minutes' if timer['mode'] == 'Break' else 'study_minutes']
    timer.update(running=False, deadline=None, remaining=minutes * 60, total=minutes * 60)
    return True


def read_user(token):
    return update_user(token)


def update_user(token, changes=None, expected_revision=None, timer_action=None):
    # All operations lock in the same order: accounts first, then the user's file.
    with FileLock(str(auth_path()) + '.lock', timeout=10):
        user_id = session_user(read_accounts(), token)
        path = user_path(user_id)
        with FileLock(str(path) + '.lock', timeout=10):
            data = read_json(path, None)
            if data is None:
                raise ValueError('Your saved data is missing. Restore it from your volume backup.')
            changed = settle_timer(data)
            # A stale browser must refresh instead of overwriting a newer device's work.
            if expected_revision is not None and data['revision'] != expected_revision:
                raise ConflictError('Your data changed on another device. Please try again.')
            if changes:
                if 'subjects' in changes:
                    validate_subjects(changes['subjects'])
                    data['subjects'] = changes['subjects']
                if 'settings' in changes:
                    settings = dict(changes['settings'])
                    valid_number(settings['daily_hours'], 0.5, 24)
                    settings['study_minutes'] = int(valid_number(settings['study_minutes'], 1, 240, whole=True))
                    settings['break_minutes'] = int(valid_number(settings['break_minutes'], 1, 120, whole=True))
                    data['settings'] = settings
                changed = True
            if timer_action:
                timer = data['timer']
                if timer_action == 'start':
                    if not timer['running']:
                        if timer['remaining'] == timer['total']:
                            key = 'study_minutes' if timer['mode'] == 'Study' else 'break_minutes'
                            timer['remaining'] = timer['total'] = data['settings'][key] * 60
                        timer.update(running=True, deadline=time.time() + timer['remaining'])
                elif timer_action == 'pause':
                    if timer['running']:
                        timer['remaining'] = max(0, math.ceil(timer['deadline'] - time.time()))
                        timer.update(running=False, deadline=None)
                elif timer_action in ('reset', 'switch'):
                    mode = 'Study' if timer_action == 'reset' or timer['mode'] == 'Break' else 'Break'
                    minutes = data['settings']['study_minutes' if mode == 'Study' else 'break_minutes']
                    timer.update(mode=mode, remaining=minutes * 60, total=minutes * 60,
                                 running=False, deadline=None)
                else:
                    raise ValueError('Invalid timer action.')
                changed = True
            if changed:
                data['revision'] += 1
                atomic_write_json(path, data)
            return data
