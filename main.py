from nicegui import app, ui, core, Client
from datetime import date
from fastapi import Request
from fastapi.responses import RedirectResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.concurrency import run_in_threadpool
from urllib.parse import parse_qs
import hmac
import math
import os
import secrets
import time

import studyflow_store as store


COLORS = ['#8B5CF6', '#3B82F6', '#06B6D4', '#10B981',
          '#F59E0B', '#EC4899', '#EF4444', '#6366F1']
SESSION_SECRET = os.environ.get('STUDYFLOW_SESSION_SECRET', '')
if len(SESSION_SECRET) < 32:
    raise RuntimeError('Set STUDYFLOW_SESSION_SECRET to a random secret of at least 32 characters.')
ON_RAILWAY = bool(os.environ.get('RAILWAY_ENVIRONMENT_ID') or os.environ.get('RAILWAY_VOLUME_MOUNT_PATH'))
SECURE_COOKIES = ON_RAILWAY or os.environ.get('STUDYFLOW_SECURE_COOKIES', 'false').lower() == 'true'


@app.middleware('http')
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    return response


app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET,
                   session_cookie='studyflow_session', max_age=store.SESSION_SECONDS,
                   same_site='lax', https_only=SECURE_COOKIES)


# Bind NiceGUI socket messages to the browser that created the page.
# A client_id alone is not proof that a visitor owns that dashboard.
def socket_allowed(sid, client_id, environ=None):
    environ = environ or core.sio.get_environ(sid) or {}
    session = environ.get('asgi.scope', {}).get('session', {})
    client = Client.instances.get(client_id)
    if not client or not client.request:
        return False
    original = client.request.session
    if not session.get('csrf') or not hmac.compare_digest(session['csrf'], original.get('csrf', '')):
        return False
    if not hmac.compare_digest(session.get('token', ''), original.get('token', '')):
        return False
    return client.request.url.path != '/' or bool(store.current_user(session.get('token', '')))


original_connect = core.sio.handlers['/']['connect']
original_handshake = core.sio.handlers['/']['handshake']
original_event = core.sio.handlers['/']['event']


@core.sio.on('connect')
async def secure_connect(sid, environ, auth=None):
    client_id = parse_qs(environ.get('QUERY_STRING', '')).get('client_id', [''])[0]
    if not socket_allowed(sid, client_id, environ):
        return False
    return await original_connect(sid, environ, auth)


@core.sio.on('handshake')
async def secure_handshake(sid, data):
    if not socket_allowed(sid, data.get('client_id')):
        return False
    return await original_handshake(sid, data)


@core.sio.on('event')
def secure_event(sid, message):
    if socket_allowed(sid, message.get('client_id')):
        original_event(sid, message)


def csrf_field(request):
    ui.element('input').props(f'type=hidden name=csrf_token value="{request.session["csrf"]}"')


@app.post('/auth/{action}')
async def auth_submit(action: str, request: Request):
    if action not in ('login', 'signup', 'logout'):
        return PlainTextResponse('Not found', status_code=404)
    body = b''
    async for chunk in request.stream():
        if len(body) + len(chunk) > 4096:
            return PlainTextResponse('Form is too large', status_code=413)
        body += chunk
    try:
        values = parse_qs(body.decode('utf-8'), max_num_fields=4, keep_blank_values=True)
        if any(len(items) != 1 for items in values.values()):
            raise ValueError('Duplicate form fields')
        form = {key: items[0] for key, items in values.items()}
    except (UnicodeDecodeError, ValueError):
        return PlainTextResponse('Invalid form', status_code=400)
    csrf = form.get('csrf_token', '')
    expected_csrf = request.session.get('csrf')
    if not expected_csrf or not hmac.compare_digest(csrf.encode(), expected_csrf.encode()):
        return PlainTextResponse('Your form expired. Reload the page and try again.', status_code=403)
    token = request.session.get('token', '')
    if action == 'logout':
        await run_in_threadpool(store.logout, token)
        request.session.clear()
        return RedirectResponse('/login', status_code=303)
    username, password = form.get('username', ''), form.get('password', '')
    if not isinstance(username, str) or not isinstance(password, str):
        return PlainTextResponse('Invalid form', status_code=400)
    try:
        # Use the connection address. Never trust a user-supplied X-Forwarded-For here.
        address = request.client.host if request.client else 'unknown'
        new_token = await run_in_threadpool(store.authenticate, username, password,
                                           address, action == 'signup')
    except store.RateLimitError:
        return RedirectResponse(f'/{action}?error=limited', status_code=303,
                                headers={'Retry-After': '900'})
    except ValueError:
        return RedirectResponse(f'/{action}?error=invalid', status_code=303)
    if token:
        await run_in_threadpool(store.logout, token)
    # Rotate both the login token and form token after authentication.
    request.session.clear()
    request.session.update(token=new_token, csrf=secrets.token_urlsafe(32))
    return RedirectResponse('/', status_code=303)


def notice(message, icon='check_circle'):
    ui.notify(message, position='top', timeout=2500,
              color='#292342', text_color='white', icon=icon)


def apply_theme():
    ui.dark_mode().enable()
    ui.colors(primary='#8B5CF6', accent='#A855F7')
    ui.add_head_html('''
    <style>
    @layer overrides {
    body {background:radial-gradient(ellipse at top left,#231744,#11162a 48%,#090d18);
          color:#f4f2ff;min-height:100vh}
    .glass {background:#191d32!important;border:1px solid #343650;
            border-radius:18px!important}
    .subject-expansion {background:#191d32!important;border:1px solid #343650;
            border-radius:15px!important;overflow:hidden}
    .subject-expansion .q-item {min-height:64px}
    .subject-expansion .q-expansion-item__content {padding:0 14px 14px}
    .q-btn.add-subject-btn {
        background:linear-gradient(120deg,#7545D9,#A855F7)!important;
        color:white!important;
        border-radius:14px!important;
        font-weight:600;
        padding:10px 18px!important;
        box-shadow:0 4px 18px #7545D955;
        transition:.2s
    }
    .add-subject-btn:hover {transform:translateY(-2px)}
    .q-notification {width:min(400px,calc(100vw - 28px));min-height:65px;
        background:#30254d!important;border:1px solid #7963b4;
        border-left:4px solid #a78bfa;border-radius:14px!important;
        padding:15px 18px!important}
    .workload-summary {border:1px solid #514365;border-radius:14px;padding:16px;
        background:#211c32;width:100%}
    .workload-summary.is-balanced {border-color:#3e535c;background:#192530}
    .workload-stats {display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;width:100%}
    .workload-value {font-size:18px;font-weight:600;color:#e3d5ff;overflow-wrap:anywhere}
    .workload-summary.is-balanced .workload-value {color:#bfdcda}
    .focus-card {background:#151326!important;border:1px solid #393052!important;
        overflow:hidden;isolation:isolate}
    .focus-expanded {
        position:fixed!important;inset:0!important;z-index:500!important;
        width:100vw!important;height:100dvh!important;max-width:none!important;
        border:0!important;border-radius:0!important;overflow:hidden!important;
        justify-content:center!important;padding:24px!important;
        background:#0d0d20!important
    }
    .focus-expanded::before {
        content:"";position:absolute;inset:-25%;z-index:-1;
        background:
          radial-gradient(ellipse 35% 30% at 25% 35%,#64369c88,transparent 90%),
          radial-gradient(ellipse 38% 35% at 75% 65%,#352e8588,transparent 90%),
          radial-gradient(ellipse 25% 30% at 55% 85%,#753b9b55,transparent 90%);
        filter:blur(35px);
        animation:nebulaMove 35s ease-in-out infinite alternate;
        pointer-events:none
    }
    .focus-expanded::after {
        content:"";position:absolute;inset:0;z-index:-1;
        background-image:
          radial-gradient(1px 1px at 11% 16%,#ffffffbb 99%,transparent),
          radial-gradient(1px 1px at 37% 72%,#c4b5fdaa 99%,transparent),
          radial-gradient(1px 1px at 81% 31%,#ffffff88 99%,transparent),
          radial-gradient(1px 1px at 63% 89%,#bda6ff99 99%,transparent);
        background-size:337px 293px;
        animation:starsMove 90s linear infinite;
        pointer-events:none
    }
    @keyframes nebulaMove {
        from {transform:translate(-3%,-2%) rotate(-4deg)}
        to {transform:translate(4%,3%) rotate(5deg)}
    }
    @keyframes starsMove {
        from {background-position:0 0}
        to {background-position:337px -293px}
    }
    .q-btn.focus-primary {background:#793dc0!important;color:white!important;
        border-radius:12px!important;box-shadow:none!important;
        font-weight:600;padding:9px 22px!important}
    .q-btn.focus-primary:hover {background:#8950cc!important}
    .q-btn.focus-secondary {background:#29243e!important;border:1px solid #4b4269!important;
        border-radius:12px!important;color:#e2d5ff!important}
    .focus-badge {background:#2a2442;border:1px solid #403659;border-radius:99px;
        padding:7px 14px;color:#d6c5fb}
    .focus-ring .q-circular-progress__circle {stroke-linecap:round}
    .celebrate {font-size:70px;animation:pop .9s infinite alternate}
    @keyframes pop {from{transform:scale(.9)}to{transform:scale(1.13)}}
    body {font-family:"Segoe UI",Roboto,Arial,sans-serif;line-height:1.6}
    .nicegui-content {padding:0;gap:0}
    .q-card.glass {box-shadow:0 6px 24px #090d1828}
    .q-btn {min-height:42px;text-transform:none;transition:background .18s,box-shadow .18s}
    .q-btn:focus-visible,.q-field:focus-within {outline:2px solid #c4b5fd;outline-offset:3px}
    .q-dialog__inner > .q-card {padding:24px;gap:18px}
    .q-field {max-width:100%}
    .q-field__control {border-radius:10px!important}
    .q-expansion-item__label {overflow-wrap:anywhere}
    .duration-field {width:100%;gap:8px}
    .duration-stepper {width:100%;gap:8px;padding:6px;border:1px solid #48415f;
        border-radius:13px;background:#19172c;align-items:center;flex-wrap:nowrap}
    .duration-stepper:focus-within {border-color:#aa85ef;box-shadow:0 0 0 3px #8b5cf618}
    .duration-stepper .q-btn {width:40px;min-width:40px;height:40px;min-height:40px;
        border-radius:8px;background:#302640;color:#e5d5ff}
    .duration-stepper .q-btn:hover {background:#483260}
    .duration-number {flex:1;min-width:0}
    .duration-stepper .duration-number:focus-within {outline:none}
    .duration-number input {text-align:center;font-size:17px;font-variant-numeric:tabular-nums;
        appearance:textfield;-moz-appearance:textfield}
    .duration-number input::-webkit-inner-spin-button,
    .duration-number input::-webkit-outer-spin-button {-webkit-appearance:none;margin:0}
    .duration-number .q-field__suffix {font-size:12px;color:#aaa0bf;padding-left:4px}
    .duration-preview {color:#cdb8f3;font-size:13px;padding-left:2px;font-variant-numeric:tabular-nums}
    .auth-shell {position:relative;isolation:isolate;overflow:hidden;min-height:100dvh;
        padding:48px 24px;justify-content:center;align-items:center;
        background:radial-gradient(ellipse at 18% 22%,#4d26743d,transparent 52%),
            radial-gradient(ellipse at 85% 80%,#34327836,transparent 48%),
            radial-gradient(ellipse at 55% 0%,#251d433d,transparent 60%),#0b0d1c}
    .auth-shell::before {content:"";position:absolute;inset:0;z-index:-1;pointer-events:none;
        background-image:radial-gradient(1px 1px at 12% 19%,#ddd5ff85 95%,transparent),
            radial-gradient(1px 1px at 84% 14%,#ddd5ff66 95%,transparent),
            radial-gradient(1px 1px at 72% 73%,#ddd5ff66 95%,transparent),
            radial-gradient(1px 1px at 21% 85%,#ddd5ff55 95%,transparent),
            radial-gradient(1px 1px at 93% 49%,#ddd5ff55 95%,transparent);
        background-size:640px 620px}
    .auth-shell::after {content:"";position:absolute;inset:0;z-index:-1;pointer-events:none;
        background:radial-gradient(ellipse at 50% 42%,#8b5cf610,transparent 60%)}
    .q-card.auth-card {width:100%;max-width:448px;padding:38px!important;gap:24px;
        border:1px solid #84709e4d;border-radius:24px!important;
        background:linear-gradient(145deg,#211a35f5,#151728fa)!important;
        box-shadow:0 24px 80px #03051166,inset 0 1px #dfc9ff0a;
        animation:authEntrance .65s cubic-bezier(.2,.7,.3,1) both}
    .auth-brand {gap:12px;align-items:center;color:#e1d0ff}
    .auth-brand-name {font-size:25px;font-weight:650;letter-spacing:-.8px;
        text-shadow:0 0 18px #a879ea40}
    .auth-book {width:54px;height:48px;flex-shrink:0;filter:drop-shadow(0 2px 10px #a775ef50);
        animation:bookAppear 1.4s cubic-bezier(.2,.7,.25,1) both}
    .auth-book svg {width:100%;height:100%;overflow:visible}
    .book-left,.book-right {transform-origin:40px 32px;transform:rotateY(0deg);
        animation:bookOpenLeft 1.4s cubic-bezier(.2,.7,.25,1) both}
    .book-right {animation-name:bookOpenRight}
    @keyframes bookOpenLeft {from{transform:perspective(160px) rotateY(86deg)}
        to{transform:perspective(160px) rotateY(0deg)}}
    @keyframes bookOpenRight {from{transform:perspective(160px) rotateY(-86deg)}
        to{transform:perspective(160px) rotateY(0deg)}}
    @keyframes bookAppear {from{opacity:0;transform:translateY(4px) scale(.94)}
        to{opacity:1;transform:translateY(0) scale(1)}}
    @keyframes authEntrance {from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
    .auth-intro {gap:10px}
    .auth-title {margin:0;font-size:31px;font-weight:650;letter-spacing:-1px;line-height:1.2;color:#f8f5ff}
    .auth-description {color:#b1aac4;font-size:14px;line-height:1.7}
    .auth-card form {display:flex;flex-direction:column;gap:19px;width:100%}
    .auth-card .q-field__control {min-height:56px;background:#17162b;border-radius:11px!important;
        transition:box-shadow .2s,background .2s}
    .auth-card .q-field--outlined .q-field__control::before {border-color:#6a5c7f80}
    .auth-card .q-field--highlighted .q-field__control {box-shadow:0 0 0 3px #a477ef12}
    .auth-card .q-field__label,.auth-card .q-field__append {color:#b7aec9}
    .auth-card .q-field__native {color:#f4efff;caret-color:#c4a3ff;color-scheme:dark}
    /* Match browser autofill to the field surface, including focused inputs. */
    .auth-card input:autofill,
    .auth-card input:-webkit-autofill {border-radius:4px;caret-color:#c4a3ff;
        -webkit-text-fill-color:#f4efff!important;
        box-shadow:0 0 0 100px #17162b inset!important;
        -webkit-box-shadow:0 0 0 100px #17162b inset!important}
    .auth-card .auth-submit {min-height:50px;border-radius:11px!important;font-size:15px;
        box-shadow:0 5px 22px #8645e52b;transition:transform .2s,box-shadow .2s,filter .2s}
    .auth-card .auth-submit:hover {transform:translateY(-1px);filter:brightness(1.08);
        box-shadow:0 8px 26px #8645e547}
    .auth-card .auth-submit:active {transform:translateY(0)}
    .auth-footer {width:100%;justify-content:center;gap:7px;padding-top:19px;
        border-top:1px solid #7d6a961f;font-size:13px;color:#aaa2bc}
    .auth-card a {color:#cfb4ff;text-underline-offset:4px;text-decoration-color:#b38bea66;
        transition:color .2s,text-decoration-color .2s}
    .auth-card a:hover {color:#eee2ff;text-decoration-color:#eee2ff}
    .auth-help {font-size:12px;color:#aaa2bc;line-height:1.7}
    .auth-error {padding:11px 13px;border:1px solid #f299b333;background:#f299b30a;
        border-radius:10px;color:#f8b6cb;font-size:13px;width:100%}
    @media(max-width:420px) {
      .auth-shell {padding:28px 16px}
      .q-card.auth-card {padding:28px 24px!important;gap:22px;border-radius:20px!important}
      .auth-title {font-size:28px}
      .auth-brand-name {font-size:24px}
      .focus-card {padding:16px!important}
      .focus-card .focus-primary {padding:9px 12px!important}
      .focus-expanded {padding:16px!important;overflow-y:auto!important}
    }
    @media(prefers-reduced-motion:reduce) {
      *,*::before,*::after {animation:none!important;transition:none!important}
    }
    }
    </style>
    ''')


def auth_page(request, signup=False):
    if store.current_user(request.session.get('token', '')):
        return RedirectResponse('/')
    request.session.setdefault('csrf', secrets.token_urlsafe(32))
    apply_theme()
    title = 'Create your account' if signup else 'Welcome to StudyFlow'
    with ui.column().classes('w-full auth-shell'):
        with ui.card().classes('glass auth-card'):
            with ui.row().classes('auth-brand'):
                # Static SVG; CSS unfolds both pages once and leaves the book open.
                ui.html('''<svg viewBox="0 0 80 64" fill="none" aria-hidden="true">
                    <g class="book-left">
                      <path d="M40 17C30 10 16 9 6 13V51C18 47 29 49 40 56Z" fill="#593497"/>
                      <path d="M40 15C30 8 18 7 9 11V46C20 43 31 45 40 52Z"
                            fill="#e9dfff" stroke="#bda0ee" stroke-width="1.3"/>
                      <path d="M16 20C22 19 29 21 34 24M16 28C22 27 29 29 34 32M16 36C22 35 28 37 32 39"
                            stroke="#9c7bc7" stroke-width="1.6" stroke-linecap="round"/>
                    </g>
                    <g class="book-right">
                      <path d="M40 17C50 10 64 9 74 13V51C62 47 51 49 40 56Z" fill="#7546b0"/>
                      <path d="M40 15C50 8 62 7 71 11V46C60 43 49 45 40 52Z"
                            fill="#f5efff" stroke="#bda0ee" stroke-width="1.3"/>
                      <path d="M46 24C52 21 59 19 64 20M46 32C52 29 59 27 64 28M48 39C53 37 59 35 64 36"
                            stroke="#a18bba" stroke-width="1.6" stroke-linecap="round"/>
                    </g>
                    <path d="M40 16V53" stroke="#a77ddd" stroke-width="1.5" stroke-linecap="round"/>
                </svg>''').classes('auth-book')
                ui.label('StudyFlow').classes('auth-brand-name')
            with ui.column().classes('auth-intro'):
                ui.label(title).classes('auth-title').props('role=heading aria-level=1')
                ui.label('Your subjects, study plan, and focus space, together.').classes('auth-description')
            error = request.query_params.get('error')
            if error:
                message = ('Too many attempts. Try again in 15 minutes.' if error == 'limited' else
                           'Check your details and try again.' if signup else
                           'Invalid username or password.')
                ui.label(message).classes('auth-error').props('role=alert')
            action = 'signup' if signup else 'login'
            with ui.element('form').props(f'method=post action=/auth/{action}'):
                csrf_field(request)
                ui.input('Username').props('name=username autocomplete=username required maxlength=40 outlined')
                ui.input('Password', password=True, password_toggle_button=True).props(
                    'name=password required minlength=12 maxlength=128 outlined '
                    + ('autocomplete=new-password' if signup else 'autocomplete=current-password'))
                if signup:
                    ui.label('Username: 3–40 letters, numbers, or underscores. '
                             'Password: 12–128 characters.').classes('auth-help')
                ui.button('Sign up' if signup else 'Log in').props('type=submit unelevated') \
                    .classes('add-subject-btn auth-submit w-full')
            with ui.row().classes('auth-footer'):
                ui.label('Already have an account?' if signup else 'New to StudyFlow?')
                ui.link('Log in' if signup else 'Create an account', '/login' if signup else '/signup')


@ui.page('/login', title='Log in | StudyFlow')
def login_page(request: Request):
    return auth_page(request)


@ui.page('/signup', title='Sign up | StudyFlow')
def signup_page(request: Request):
    return auth_page(request, signup=True)


def format_duration(hours):
    """Round only for display; a positive workload always shows at least one minute."""
    if not math.isfinite(hours) or hours < 0:
        raise ValueError('Duration must be a finite, non-negative number.')
    minutes = max(1, math.floor(hours * 60 + 0.5)) if hours > 0 else 0
    whole_hours, minutes = divmod(minutes, 60)
    parts = []
    if whole_hours:
        parts.append(f'{whole_hours} hr' + ('s' if whole_hours != 1 else ''))
    if minutes or not whole_hours:
        parts.append(f'{minutes} min')
    return ' '.join(parts)


def duration_input(label, value, minimum, maximum):
    """Keep an editable numeric field; show time clearly and step by 15 minutes."""
    with ui.column().classes('duration-field'):
        ui.label(label).classes('text-sm text-gray-300')
        with ui.row().classes('duration-stepper'):
            decrease = ui.button(icon='remove').props(f'flat aria-label="Decrease {label}"')
            field = ui.number(label, value=value, min=minimum, max=maximum, step=0.25,
                              suffix='hrs').props('borderless dense hide-bottom-space inputmode=decimal') \
                .classes('duration-number')
            field.props(remove='label')  # The visible label sits above the whole control.
            field.props(f'aria-label="{label}"')
            increase = ui.button(icon='add').props(f'flat aria-label="Increase {label}"')
        preview = ui.label().classes('duration-preview').props('aria-live=polite')

    def normalize():
        if field.value is not None and math.isfinite(field.value):
            # Round input only, never the study planning calculations.
            field.value = max(minimum, min(maximum, round(field.value, 2)))

    def step(direction):
        if field.value is not None and math.isfinite(field.value):
            field.value = max(minimum, min(maximum, round(field.value + direction * 0.25, 2)))

    field.on_value_change(normalize)
    field.on('keydown.up.prevent', lambda: step(1))
    field.on('keydown.down.prevent', lambda: step(-1))
    normalize()
    preview.bind_text_from(field, 'value', backward=lambda value:
                          format_duration(value) if value is not None and math.isfinite(value) and value >= 0
                          else 'Enter a study duration')
    decrease.on_click(lambda: step(-1)).bind_enabled_from(field, 'value',
        backward=lambda value: value is not None and math.isfinite(value) and value > minimum)
    increase.on_click(lambda: step(1)).bind_enabled_from(field, 'value',
        backward=lambda value: value is not None and math.isfinite(value) and value < maximum)
    return field


def remaining_days(subject):
    return max((date.fromisoformat(subject['exam_date']) - date.today()).days, 0)


def progress(subject):
    chapters = subject['chapters']
    return round(100 * sum(c['completed'] for c in chapters) / len(chapters)) if chapters else 0


def remaining_hours(subject):
    return sum(float(c['hours']) for c in subject['chapters'] if not c['completed'])


def recommended_hours(subject):
    factor = {'Easy': 1, 'Medium': 1.15, 'Hard': 1.3}.get(subject['difficulty'], 1)
    days = remaining_days(subject)
    hours = remaining_hours(subject) * factor
    return max(0.1, hours / days) if days and hours else hours


def analyze_workload(subjects, daily_hours):
    """Check cumulative deadlines against one shared budget, excluding exam day."""
    if not math.isfinite(daily_hours) or daily_hours < 0:
        raise ValueError('Daily study hours must be finite and non-negative.')
    pending = sorted((s for s in subjects if remaining_hours(s) > 0), key=lambda s: (
        s['exam_date'], -{'Easy': 1, 'Medium': 2, 'Hard': 3}.get(s['difficulty'], 2)))
    rows, deadlines, workloads, allocations = [], [], [], []
    for subject in pending:
        hours = remaining_hours(subject)
        days = remaining_days(subject)
        recommendation = recommended_hours(subject) if days else 0
        budget = max(0, daily_hours - math.fsum(allocations))
        allocated = min(budget, hours, recommendation) if days else 0
        total = math.fsum(allocations + [allocated])
        while total > daily_hours:
            # Correct binary addition overflow without rounding the workload.
            allocated = max(0, allocated - (total - daily_hours))
            total = math.fsum(allocations + [allocated])
        allocations.append(allocated)
        rows.append({'subject': subject, 'remaining': hours, 'days': days,
                     'recommended': recommendation, 'allocated': allocated})
        workloads.append(hours)
        required = math.fsum(workloads)
        available = days * daily_hours
        # Ignore floating-point noise, but keep genuine fractional shortfalls.
        extra = 0 if math.isclose(required, available, rel_tol=1e-12, abs_tol=1e-9) \
            else max(0, required - available)
        deadline = {'date': subject['exam_date'], 'days': days, 'required': required,
                    'available': available, 'extra': extra}
        if deadlines and deadlines[-1]['date'] == subject['exam_date']:
            deadlines[-1] = deadline  # Subjects sharing an exam date share the same capacity.
        else:
            deadlines.append(deadline)
    conflicts = [deadline for deadline in deadlines if deadline['extra'] > 0]
    summary = max(conflicts, key=lambda deadline: deadline['extra']) if conflicts \
        else (deadlines[-1] if deadlines else None)
    # The largest cumulative deficit is the total extra time, not the sum of deficits.
    return {'rows': rows, 'deadlines': deadlines, 'summary': summary,
            'urgent': conflicts[0] if conflicts else None,
            'extra_needed': summary['extra'] if summary else 0,
            'allocated_today': math.fsum(allocations),
            'recommended_today': math.fsum(row['recommended'] for row in rows)}


@ui.page('/', title='StudyFlow')
def dashboard(request: Request):
    token = request.session.get('token', '')
    if not store.current_user(token):
        return RedirectResponse('/login')
    request.session.setdefault('csrf', secrets.token_urlsafe(32))
    apply_theme()
    user_data = store.read_user(token)
    subjects = list(user_data['subjects'])
    sessions = dict(user_data['sessions'])
    selected_subject = None
    opened_subject = [None]
    syncing_settings = False
    plan_date = date.today()

    def save_data():
        nonlocal user_data
        try:
            user_data = store.update_user(token, {'subjects': subjects}, user_data['revision'])
            sessions.update(user_data['sessions'])
            return True
        except store.AuthenticationError:
            ui.navigate.to('/login')
        except (ValueError, OSError, TimeoutError) as error:
            notice(str(error) if isinstance(error, ValueError) else 'Unable to save. Please try again.', 'warning')
            try:
                user_data = store.read_user(token)
                subjects[:] = user_data['subjects']
                refresh_all()
            except (ValueError, OSError, TimeoutError):
                pass  # Keep the error visible; never replace unreadable saved data.
        return False

    def today_sessions():
        return sessions['completed'] if sessions['date'] == date.today().isoformat() else 0

    def set_settings_controls(settings):
        nonlocal syncing_settings
        syncing_settings = True
        try:
            daily_hours.set_value(settings['daily_hours'])
            study_minutes.set_value(settings['study_minutes'])
            break_minutes.set_value(settings['break_minutes'])
        finally:
            syncing_settings = False

    def save_settings():
        nonlocal user_data
        if syncing_settings:
            return
        settings = {'daily_hours': daily_hours.value,
                    'study_minutes': study_minutes.value, 'break_minutes': break_minutes.value}
        if settings == user_data['settings']:
            return
        try:
            user_data = store.update_user(token, {'settings': settings}, user_data['revision'])
            refresh_all()
        except store.AuthenticationError:
            ui.navigate.to('/login')
        except (ValueError, OSError, TimeoutError) as error:
            notice(str(error) if isinstance(error, ValueError) else 'Unable to save settings.', 'warning')
            set_settings_controls(user_data['settings'])

    def refresh_all():
        show_dashboard.refresh()
        show_subjects.refresh()
        show_plan.refresh()


    def save_subject():
        name = (subject_name.value or '').strip()
        if not name:
            notice('Please enter a subject name', 'warning')
            return
        if not exam_date.value:
            notice('Please select an exam date', 'warning')
            return
        try:
            chosen_date = date.fromisoformat(exam_date.value)
        except (TypeError, ValueError):
            notice('Please select a valid exam date', 'warning')
            return
        if chosen_date < date.today():
            notice('Exam date cannot be in the past', 'warning')
            return
        subjects.append({'name': name, 'difficulty': difficulty.value,
                         'exam_date': exam_date.value, 'color': subject_color.value,
                         'chapters': []})
        if not save_data():
            return
        refresh_all()
        subject_dialog.close()
        notice('Subject added')


    def open_subject_dialog():
        subject_name.value = ''
        difficulty.value = 'Medium'
        exam_date.value = ''
        subject_color.value = COLORS[0]
        show_colors.refresh()
        subject_dialog.open()


    def delete_subject(subject):
        if opened_subject[0] is subject:
            opened_subject[0] = None
        subjects.remove(subject)
        if not save_data():
            return
        refresh_all()
        notice('Subject deleted', 'delete_outline')


    def open_chapter_dialog(subject):
        nonlocal selected_subject
        selected_subject = subject
        chapter_name.value = ''
        chapter_hours.value = 1
        chapter_dialog.open()


    def save_chapter():
        name = (chapter_name.value or '').strip()
        if not any(s is selected_subject for s in subjects):
            notice('This subject changed. Reopen it before adding a chapter.', 'warning')
            return
        if not name:
            notice('Enter a name and valid study hours', 'warning')
            return
        try:
            store.valid_number(chapter_hours.value, 0.001, 10000)
        except ValueError as error:
            notice(str(error), 'warning')
            return
        selected_subject['chapters'].append({
            'name': name, 'hours': float(chapter_hours.value), 'completed': False
        })
        opened_subject[0] = selected_subject
        if not save_data():
            return
        refresh_all()
        chapter_dialog.close()
        notice('Chapter added')


    def toggle_chapter(subject, chapter, completed):
        was_complete = progress(subject) == 100
        chapter['completed'] = completed
        opened_subject[0] = subject
        if not save_data():
            return
        refresh_all()
        if completed and progress(subject) == 100 and not was_complete:
            celebration_name.set_text(subject['name'])
            celebration_dialog.open()
        elif completed:
            notice(f'{chapter["name"]} completed')


    def delete_chapter(subject, chapter):
        opened_subject[0] = subject
        subject['chapters'].remove(chapter)
        if not save_data():
            return
        refresh_all()
        notice('Chapter deleted', 'delete_outline')


    def choose_color(color):
        subject_color.value = color
        show_colors.refresh()


    def apply_custom_color():
        if custom_color.value:
            choose_color(custom_color.value)
        color_dialog.close()


    @ui.refreshable
    def show_colors():
        with ui.grid(columns=4).classes('gap-3'):
            for color in COLORS:
                selected = subject_color.value == color
                ui.button(icon='check' if selected else None,
                          on_click=lambda c=color: choose_color(c)) \
                    .props(f'round unelevated aria-label="Choose color {color}"').style(
                        f'background:{color}!important;color:white!important;'
                        'width:36px;height:36px;min-width:36px;min-height:36px;'
                        f'border:2px solid {"white" if selected else "transparent"};')


    @ui.refreshable
    def show_dashboard():
        counts = [('Subjects', len(subjects)),
                  ('Chapters', sum(len(s['chapters']) for s in subjects)),
                  ('Subjects Done', sum(1 for s in subjects if s['chapters'] and progress(s) == 100))]
        with ui.row().classes('w-full gap-2 flex-nowrap'):
            for title, value in counts:
                with ui.card().classes('glass flex-1 min-w-0 p-3 gap-1'):
                    ui.label(title).classes('text-xs text-gray-400')
                    ui.label(str(value)).classes('text-xl font-bold text-purple-300')


    @ui.refreshable
    def show_subjects():
        if not subjects:
            ui.label('Add your first subject to get started.').classes('text-gray-400')
            return
        expansions = []
        with ui.column().classes('w-full gap-2'):
            for subject in subjects:
                chapters = subject['chapters']
                with ui.expansion(
                    text=subject['name'],
                    caption=f'{progress(subject)}% completed · {remaining_days(subject)} days left',
                    icon='menu_book', value=opened_subject[0] is subject
                ).classes('subject-expansion w-full').style(
                    f'border-left:4px solid {subject["color"]}!important;') as expansion:
                    expansions.append(expansion)
                    ui.label(f'{subject["difficulty"]} · Exam {subject["exam_date"]}') \
                        .classes('text-xs text-gray-400')
                    ui.linear_progress(value=progress(subject)/100, color='purple',
                                       show_value=False).classes('w-full my-2')
                    with ui.row().classes('w-full justify-between gap-2'):
                        ui.label(f'{sum(c["completed"] for c in chapters)}/{len(chapters)} chapters') \
                            .classes('text-xs text-gray-400')
                        ui.label(f'{format_duration(remaining_hours(subject))} remaining') \
                            .classes('text-xs text-gray-400')
                    if remaining_hours(subject):
                        if remaining_days(subject) == 0:
                            ui.label('No study days remain before the exam').classes('text-xs text-gray-400')
                        else:
                            ui.label(f'Suggested: {format_duration(recommended_hours(subject))}/day') \
                                .classes('text-xs text-purple-300')
                    for chapter in chapters:
                        with ui.row().classes('w-full items-center gap-2 flex-nowrap'):
                            ui.checkbox(value=chapter['completed'],
                                on_change=lambda e, s=subject, c=chapter:
                                    toggle_chapter(s, c, e.value)).props('dense color=purple')
                            with ui.column().classes('gap-0 flex-1 min-w-0'):
                                ui.label(chapter['name']).classes('text-sm break-words').style(
                                    'text-decoration:line-through;opacity:.6' if chapter['completed'] else '')
                                ui.label(format_duration(chapter['hours'])).classes('text-xs text-gray-400')
                            ui.button(icon='delete_outline',
                                on_click=lambda s=subject, c=chapter: delete_chapter(s, c)) \
                                .props('flat round dense color=grey aria-label="Delete chapter"')
                    ui.button('Add Chapter', icon='add',
                        on_click=lambda s=subject: open_chapter_dialog(s)) \
                        .props('outline color=purple').classes('w-full')
                    ui.button('Delete Subject', icon='delete_outline',
                        on_click=lambda s=subject: delete_subject(s)) \
                        .props('flat color=grey').classes('w-full')

                def close_others(e, current=expansion, s=subject):
                    if e.value:
                        opened_subject[0] = s
                        for other in expansions:
                            if other is not current and other.value:
                                other.value = False
                    elif opened_subject[0] is s:
                        opened_subject[0] = None

                expansion.on_value_change(close_others)


    @ui.refreshable
    def show_plan():
        analysis = analyze_workload(subjects, float(daily_hours.value or 0))
        if not analysis['rows']:
            ui.label('Add chapters to generate your study plan.').classes('text-gray-400')
            return
        summary, urgent = analysis['summary'], analysis['urgent']
        with ui.column().classes('workload-summary' + ('' if urgent else ' is-balanced')):
            ui.label(f'Before {summary["date"]}').classes('text-xs text-gray-400')
            with ui.element('div').classes('workload-stats'):
                for label, value in [('Required', summary['required']), ('Available', summary['available']),
                                     ('Extra needed', summary['extra'])]:
                    with ui.column().classes('gap-1 min-w-0'):
                        ui.label(label).classes('text-xs text-gray-400')
                        ui.label(format_duration(value)).classes('workload-value')
            if not urgent:
                message = 'Your remaining workload fits before these exams.'
            elif urgent['days'] == 0:
                message = 'Check the exam date for chapters with no study days remaining.'
            elif urgent['days'] == 1:
                message = ('Consider adding 1 extra hour today.' if urgent['extra'] == 1 else
                           f'Consider adding an extra {format_duration(urgent["extra"])} today.')
            else:
                message = f'Consider adding {format_duration(urgent["extra"])} before {urgent["date"]}.'
            ui.label(message).classes('text-sm text-gray-300')
            if urgent and urgent['date'] != summary['date']:
                ui.label(f'{format_duration(urgent["extra"])} of the extra time is needed before {urgent["date"]}.') \
                    .classes('text-xs text-gray-400')
        with ui.card().classes('glass w-full p-4 gap-2'):
            ui.label(f'Allocated today: {format_duration(analysis["allocated_today"])}').classes('font-bold')
            ui.label(f'Difficulty-adjusted pace: {format_duration(analysis["recommended_today"])}/day') \
                .classes('text-xs text-gray-400')
            for row in analysis['rows']:
                subject = row['subject']
                with ui.row().classes('w-full justify-between'):
                    ui.label(subject['name']).classes('text-sm')
                    ui.label(f'{format_duration(row["allocated"])} today').classes('text-sm text-purple-300')
                details = (f'Suggested {format_duration(row["recommended"])}/day' if row['days'] else
                           'No study days before exam')
                ui.label(f'Remaining {format_duration(row["remaining"])} · Exam {subject["exam_date"]} · {details}') \
                    .classes('text-xs text-gray-400 break-words')


    with ui.dialog() as color_dialog, ui.card().classes('glass w-full max-w-sm'):
        ui.label('Custom Color').classes('text-lg font-bold')
        custom_color = ui.color_input(value=COLORS[0])
        ui.button('Apply Color', on_click=apply_custom_color).classes('w-full')

    with ui.dialog() as subject_dialog, ui.card().classes(
        'glass w-full max-w-sm max-h-[90vh] overflow-y-auto'):
        ui.label('Add New Subject').classes('text-xl font-bold')
        subject_name = ui.input('Subject Name').props('maxlength=120 outlined').classes('w-full')
        ui.label('Difficulty').classes('text-sm text-gray-400')
        difficulty = ui.toggle(['Easy', 'Medium', 'Hard'], value='Medium') \
            .props('spread unelevated').classes('w-full')
        with ui.input('Exam Date').props('readonly').classes('w-full') as exam_date:
            with ui.menu().props('no-parent-event') as date_menu:
                ui.date().props(f'min="{date.today().isoformat()}" minimal') \
                    .bind_value(exam_date).on('update:model-value', date_menu.close)
            with exam_date.add_slot('append'):
                ui.icon('event').classes('cursor-pointer').on('click', date_menu.open)
            exam_date.on('click', date_menu.open)
        exam_date.on('keydown.enter', date_menu.open)
        ui.label('Subject Color').classes('text-sm text-gray-400')
        subject_color = ui.input(value=COLORS[0]).classes('hidden')
        show_colors()
        ui.button('Custom Color', icon='palette', on_click=color_dialog.open).props('outline')
        ui.button('Save Subject', on_click=save_subject).classes('w-full')

    with ui.dialog() as chapter_dialog, ui.card().classes('glass w-full max-w-sm'):
        ui.label('Add Chapter').classes('text-xl font-bold')
        chapter_name = ui.input('Chapter Name').props('maxlength=120 outlined').classes('w-full')
        chapter_hours = duration_input('Estimated Study Hours', value=1, minimum=0.001, maximum=10000)
        ui.button('Save Chapter', on_click=save_chapter).classes('w-full')

    with ui.dialog() as celebration_dialog:
        with ui.card().classes('glass items-center text-center p-8 gap-4 w-full max-w-sm'):
            ui.label('🏆').classes('celebrate')
            ui.label('MISSION COMPLETE!').classes('text-2xl font-bold text-purple-300')
            celebration_name = ui.label('').classes('text-xl font-bold')
            ui.label('Every chapter completed. You earned this moment!') \
                .classes('text-gray-400')
            ui.button('Keep Going', on_click=celebration_dialog.close).classes('w-full')


    # ---------- MAIN PAGE ----------
    with ui.column().classes('w-full max-w-4xl mx-auto px-3 sm:px-6 py-6 gap-5'):
        with ui.row().classes('w-full items-center justify-between gap-3'):
            with ui.column().classes('gap-0'):
                ui.label('StudyFlow').classes('text-3xl font-bold text-purple-300')
                ui.label('Your personal study assistant').classes('text-gray-400 text-sm')
            with ui.row().classes('items-center gap-2'):
                ui.button('Add Subject', icon='add', on_click=open_subject_dialog) \
                    .props('unelevated no-caps').classes('add-subject-btn')
                with ui.element('form').props('method=post action=/auth/logout'):
                    csrf_field(request)
                    ui.button('Log out', icon='logout').props('type=submit flat no-caps')

        show_dashboard()

        with ui.row().classes('w-full max-w-sm'):
            daily_hours = duration_input('Available study hours per day',
                                         value=user_data['settings']['daily_hours'], minimum=0.5, maximum=24)
            daily_hours.on_value_change(save_settings)

        ui.label('My Subjects').classes('text-xl font-bold')
        show_subjects()
        ui.label('Study Plan').classes('text-xl font-bold')
        show_plan()

        # ---------- FOCUS SPACE ----------
        ui.label('Focus Space').classes('text-2xl font-bold')
        with ui.card().classes(
            'glass focus-card w-full max-w-xl mx-auto items-center p-5 sm:p-8 gap-4'
        ) as focus_card:

            expanded = [False]

            def toggle_focus_size():
                expanded[0] = not expanded[0]
                if expanded[0]:
                    focus_card.classes(add='focus-expanded')
                else:
                    focus_card.classes(remove='focus-expanded')
                expand_button.props(
                    'icon=close_fullscreen' if expanded[0] else 'icon=open_in_full'
                )

            with ui.row().classes('w-full items-center justify-between'):
                with ui.row().classes('gap-1'):
                    expand_button = ui.button(
                        icon='open_in_full', on_click=toggle_focus_size
                    ).props('flat round dense color=purple aria-label="Expand or minimize focus space"') \
                        .tooltip('Expand / Minimize')
                    ui.button(
                        icon='tune',
                        on_click=lambda: settings_panel.set_visibility(not settings_panel.visible)
                    ).props('flat round dense color=purple aria-label="Timer settings"').tooltip('Timer Settings')
                mode_label = ui.label('FOCUS SESSION').classes(
                    'text-xs font-bold tracking-widest text-purple-300'
                )

            with ui.element('div').classes(
                'relative flex items-center justify-center w-64 h-64 sm:w-72 sm:h-72'
            ):
                timer_progress = ui.circular_progress(
                    value=0, size='250px', color='purple', show_value=False
                ).props('track-color=grey-9 thickness=0.12').classes('focus-ring')
                with ui.column().classes('absolute inset-0 items-center justify-center gap-1'):
                    timer_label = ui.label('25:00').classes(
                        'text-6xl font-bold text-purple-100'
                    )
                    ui.label('DEEP WORK').classes('text-xs tracking-widest text-purple-300')

            with ui.row().classes('gap-4 flex-wrap justify-center') as settings_panel:
                study_minutes = ui.number('Focus minutes', value=user_data['settings']['study_minutes'], min=1, max=240) \
                    .classes('w-32')
                break_minutes = ui.number('Break minutes', value=user_data['settings']['break_minutes'], min=1, max=120) \
                    .classes('w-32')
            settings_panel.set_visibility(False)

            study_minutes.on_value_change(save_settings)
            break_minutes.on_value_change(save_settings)
            timer_state = user_data['timer'].copy()

            def update_timer_display():
                seconds = timer_state['remaining']
                timer_label.set_text(f'{seconds // 60:02d}:{seconds % 60:02d}')
                timer_progress.value = (
                    1 - seconds / timer_state['total'] if timer_state['total'] else 0
                )
                mode_label.set_text(
                    'FOCUS SESSION' if timer_state['mode'] == 'Study' else 'BREAK SESSION'
                )
                switch_button.set_text(
                    'Switch to Break' if timer_state['mode'] == 'Study'
                    else 'Switch to Focus'
                )

            def change_timer(action):
                nonlocal user_data
                try:
                    user_data = store.update_user(token, expected_revision=user_data['revision'],
                                                  timer_action=action)
                    sessions.update(user_data['sessions'])
                    timer_state.update(user_data['timer'])
                    update_timer_display()
                except store.AuthenticationError:
                    ui.navigate.to('/login')
                except (OSError, ValueError, TimeoutError) as error:
                    notice(str(error) if isinstance(error, ValueError) else
                           'Unable to save the timer. Please try again.', 'warning')

            def start_timer():
                change_timer('start')
                if not expanded[0]:
                    toggle_focus_size()

            def pause_timer():
                change_timer('pause')

            def reset_timer():
                change_timer('reset')

            def switch_mode():
                change_timer('switch')

            with ui.row().classes('gap-3 flex-nowrap items-center justify-center w-full'):
                ui.button(icon='restart_alt', on_click=reset_timer) \
                    .props('flat round aria-label="Reset timer"').classes('focus-secondary').tooltip('Reset')
                pause_button = ui.button(icon='pause', on_click=pause_timer) \
                    .props('flat round aria-label="Pause timer"').classes('focus-secondary').tooltip('Pause')
                start_button = ui.button('Start Focus', icon='play_arrow', on_click=start_timer) \
                    .props('unelevated no-caps').classes('focus-primary')

            switch_button = ui.button(
                'Switch to Break', icon='arrow_forward', on_click=switch_mode
            ).props('flat no-caps color=purple').classes('text-sm')

            with ui.row().classes('focus-badge items-center gap-2 mt-2'):
                ui.icon('check_circle_outline').classes('text-purple-300')
                sessions_label = ui.label('').classes('text-xs')

            def update_sessions():
                count = today_sessions()
                sessions_label.set_text(
                    f'{count} session{"s" if count != 1 else ""} completed today'
                )

            update_sessions()

            def tick():
                nonlocal user_data, plan_date
                try:
                    latest = store.read_user(token)
                except store.AuthenticationError:
                    polling.deactivate()
                    ui.navigate.to('/login')
                    return
                except (OSError, ValueError, TimeoutError):
                    polling.deactivate()
                    notice('Unable to read saved data. Reload to try again.', 'warning')
                    return
                if date.today() != plan_date:
                    plan_date = date.today()
                    refresh_all()  # Deadlines also change when the calendar day rolls over.
                if latest['revision'] != user_data['revision']:
                    subjects_changed = latest['subjects'] != user_data['subjects']
                    settings_changed = latest['settings'] != user_data['settings']
                    finished = (timer_state['running'] and not latest['timer']['running']
                                and timer_state['deadline'] <= time.time())
                    user_data = latest
                    if subjects_changed:
                        subjects[:] = latest['subjects']
                    sessions.update(latest['sessions'])
                    # Programmatic changes must not save partially updated controls.
                    set_settings_controls(latest['settings'])
                    if subjects_changed or settings_changed:
                        refresh_all()
                    timer_state.update(latest['timer'])
                    if finished:
                        notice('Focus session completed!' if timer_state['mode'] == 'Break'
                               else 'Break finished. Ready to focus?', 'timer')
                sessions.update(latest['sessions'])
                timer_state.update(latest['timer'])
                if timer_state['running']:
                    timer_state['remaining'] = max(0, math.ceil(timer_state['deadline'] - time.time()))
                update_timer_display()
                start_button.set_text(
                    ('Focusing...' if timer_state['mode'] == 'Study' else 'On Break...')
                    if timer_state['running'] else
                    ('Start Focus' if timer_state['mode'] == 'Study' else 'Start Break'))
                update_sessions()

            update_timer_display()
            polling = ui.timer(1, tick)


if __name__ in {'__main__', '__mp_main__'}:
    ui.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)),
           reload=False, show=False)
