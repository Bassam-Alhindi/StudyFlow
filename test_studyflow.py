"""Run with: python -m unittest -v test_studyflow (uses temporary data only)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import base64
import copy
import http.cookiejar
import json
import math
import os
import secrets
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from fastapi import Request
from itsdangerous import TimestampSigner

os.environ.setdefault('STUDYFLOW_SESSION_SECRET', secrets.token_urlsafe(48))
import main
import studyflow_store as store


PASSWORD = 'Temporary-test-password-123'


def sample_subject():
    return {'name': 'Algorithms', 'difficulty': 'Hard', 'color': '#8B5CF6',
            'exam_date': (date.today() + timedelta(days=3)).isoformat(),
            'chapters': [{'name': 'Graphs', 'hours': 3, 'completed': False},
                         {'name': 'Trees', 'hours': 3, 'completed': False}]}


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.folder = TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.location = patch.object(store, 'PRIVATE_DIR', Path(self.folder.name) / 'private')
        self.location.start()
        self.addCleanup(self.location.stop)
        self.alpha = store.authenticate('alpha', PASSWORD, 'alpha-ip', signup=True)
        self.beta = store.authenticate('beta', PASSWORD, 'beta-ip', signup=True)

    def test_passwords_are_salted_argon2_hashes(self):
        accounts = store.read_accounts()
        hashes = [user['password_hash'] for user in accounts['users'].values()]
        self.assertTrue(all(h.startswith('$argon2id$') for h in hashes))
        self.assertNotEqual(hashes[0], hashes[1])
        self.assertNotIn(PASSWORD, store.auth_path().read_text())
        self.assertNotIn(self.alpha, store.auth_path().read_text())

    def test_login_case_normalization_and_duplicate_signup(self):
        token = store.authenticate(' ALPHA ', PASSWORD, 'another-device')
        self.assertEqual(store.current_user(token), store.current_user(self.alpha))
        with self.assertRaises(ValueError):
            store.authenticate('Alpha', PASSWORD, 'another-ip', signup=True)

    def test_wrong_password_and_unknown_user(self):
        for username in ('alpha', 'unknown'):
            with self.assertRaises(store.AuthenticationError):
                store.authenticate(username, 'Incorrect-password-123', 'bad-ip')

    def test_server_side_credential_validation(self):
        for username, password in [('../escape', PASSWORD), ('x', PASSWORD), ('new_user', 'short')]:
            with self.assertRaises(ValueError):
                store.authenticate(username, password, 'validation-ip', signup=True)

    def test_rate_limit_per_account_survives_different_ips(self):
        for attempt in range(5):
            with self.assertRaises(store.AuthenticationError):
                store.authenticate('alpha', 'Wrong-password-123', f'ip-{attempt}')
        with self.assertRaises(store.RateLimitError):
            store.authenticate('alpha', PASSWORD, 'fresh-ip')

    def test_rate_limit_per_ip_survives_different_usernames(self):
        for attempt in range(20):
            with self.assertRaises(ValueError):
                store.authenticate(f'user_{attempt}', 'short', 'same-ip')
        with self.assertRaises(store.RateLimitError):
            store.authenticate('alpha', PASSWORD, 'same-ip')

    def test_user_subjects_progress_settings_and_timers_are_isolated(self):
        subject = sample_subject()
        subject['chapters'][0]['completed'] = True
        store.update_user(self.alpha, {'subjects': [subject], 'settings':
                          {'daily_hours': 5, 'study_minutes': 30, 'break_minutes': 7}})
        store.update_user(self.alpha, timer_action='start')
        alpha = store.read_user(self.alpha)
        beta = store.read_user(self.beta)
        self.assertEqual(alpha['subjects'], [subject])
        self.assertEqual(beta, store.new_user_data())
        self.assertTrue(alpha['timer']['running'])
        self.assertEqual(alpha['timer']['total'], 1800)
        self.assertEqual(main.progress(subject), 50)
        self.assertEqual(main.remaining_hours(subject), 3)

    def test_returned_objects_do_not_share_mutable_state(self):
        first = store.read_user(self.alpha)
        first['settings']['daily_hours'] = 20
        self.assertEqual(store.read_user(self.alpha)['settings']['daily_hours'], 3)

    def test_timer_pause_resume_reset_switch(self):
        with patch.object(store.time, 'time', return_value=time.time()):
            start = store.update_user(self.alpha, timer_action='start')['timer']
        with patch.object(store.time, 'time', return_value=start['deadline'] - 120):
            paused = store.update_user(self.alpha, timer_action='pause')['timer']
            self.assertEqual(paused['remaining'], 120)
            resumed = store.update_user(self.alpha, timer_action='start')['timer']
            self.assertEqual(resumed['remaining'], 120)
        switched = store.update_user(self.alpha, timer_action='switch')['timer']
        self.assertEqual((switched['mode'], switched['remaining']), ('Break', 300))
        reset = store.update_user(self.alpha, timer_action='reset')['timer']
        self.assertEqual((reset['mode'], reset['remaining'], reset['running']), ('Study', 1500, False))

    def test_timer_settings_from_numeric_controls_use_integer_seconds(self):
        store.update_user(self.alpha, {'settings': {'daily_hours': 3.5,
                          'study_minutes': 30.0, 'break_minutes': 7.0}})
        data = store.update_user(self.alpha, timer_action='reset')
        self.assertIsInstance(data['timer']['remaining'], int)
        self.assertEqual(data['timer']['remaining'], 1800)

    def test_timer_completion_is_counted_once_across_devices(self):
        started = store.update_user(self.alpha, timer_action='start')
        with patch.object(store.time, 'time', return_value=started['timer']['deadline'] + 1):
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(lambda _: store.read_user(self.alpha), range(12)))
        self.assertTrue(all(data['sessions']['completed'] == 1 for data in results))
        self.assertEqual(store.read_user(self.beta)['sessions']['completed'], 0)
        self.assertEqual(store.read_user(self.alpha)['timer']['mode'], 'Break')

    def test_break_completion_does_not_increment_study_count(self):
        store.update_user(self.alpha, timer_action='switch')
        data = store.update_user(self.alpha, timer_action='start')
        with patch.object(store.time, 'time', return_value=data['timer']['deadline'] + 1):
            ended = store.read_user(self.alpha)
        self.assertEqual(ended['sessions']['completed'], 0)
        self.assertEqual(ended['timer']['mode'], 'Study')

    def test_stale_device_cannot_overwrite_saved_subjects(self):
        revision = store.read_user(self.alpha)['revision']
        store.update_user(self.alpha, {'subjects': [sample_subject()]}, revision)
        with self.assertRaises(store.ConflictError):
            store.update_user(self.alpha, {'subjects': []}, revision)
        self.assertEqual(len(store.read_user(self.alpha)['subjects']), 1)

    def test_nonfinite_hours_and_invalid_settings_are_rejected(self):
        for value in (float('nan'), float('inf'), -1, 0):
            subject = sample_subject()
            subject['chapters'][0]['hours'] = value
            with self.assertRaises(ValueError):
                store.update_user(self.alpha, {'subjects': [subject]})
        with self.assertRaises(ValueError):
            store.update_user(self.alpha, {'settings': {'daily_hours': 100, 'study_minutes': 25, 'break_minutes': 5}})
        self.assertEqual(store.read_user(self.alpha)['revision'], 0)

    def test_logout_and_expiry_reject_reads_and_writes(self):
        store.logout(self.alpha)
        for operation in (store.read_user, lambda token: store.update_user(token, timer_action='start')):
            with self.assertRaises(store.AuthenticationError):
                operation(self.alpha)
        with patch.object(store.time, 'time', return_value=time.time() + store.SESSION_SECONDS + 1):
            self.assertIsNone(store.current_user(self.beta))
            with self.assertRaises(store.AuthenticationError):
                store.read_user(self.beta)

    def test_socket_client_id_cannot_be_reused_by_another_browser_or_account(self):
        owner_session = {'csrf': 'owner-form-token', 'token': self.alpha}
        request = Request({'type': 'http', 'path': '/', 'scheme': 'http',
                           'server': ('localhost', 80), 'headers': [], 'session': owner_session})
        client = SimpleNamespace(request=request)
        def environment(session):
            return {'asgi.scope': {'session': session}}
        with patch.dict(main.Client.instances, {'owner-client': client}, clear=True):
            self.assertTrue(main.socket_allowed('owner', 'owner-client', environment(owner_session)))
            for attacker in ({}, {'csrf': 'different-browser', 'token': self.alpha},
                             {'csrf': 'owner-form-token', 'token': self.beta}):
                self.assertFalse(main.socket_allowed('attacker', 'owner-client', environment(attacker)))
                with patch.object(main.core.sio, 'get_environ', return_value=environment(attacker)), \
                     patch.object(main, 'original_event') as event:
                    main.secure_event('attacker', {'client_id': 'owner-client'})
                    event.assert_not_called()
            store.logout(self.alpha)
            self.assertFalse(main.socket_allowed('owner', 'owner-client', environment(owner_session)))

    def test_atomic_write_failure_preserves_existing_json(self):
        path = store.user_path(store.current_user(self.alpha))
        before = path.read_bytes()
        with patch.object(store.os, 'replace', side_effect=OSError('simulated disk failure')):
            with self.assertRaises(OSError):
                store.update_user(self.alpha, timer_action='start')
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(path.parent.glob('*.tmp')), [])

    def test_corrupt_json_is_not_silently_overwritten(self):
        path = store.user_path(store.current_user(self.alpha))
        path.write_text('corrupt', encoding='utf-8')
        with self.assertRaises(ValueError):
            store.update_user(self.alpha, timer_action='start')
        self.assertEqual(path.read_text(), 'corrupt')

    def test_independent_processes_preserve_all_updates_and_saved_deadline(self):
        started = store.update_user(self.alpha, timer_action='start')
        env = os.environ.copy()
        env.update(TEST_PRIVATE_DIR=str(store.PRIVATE_DIR), TEST_TOKEN=self.alpha)
        script = ("import os; from pathlib import Path; import studyflow_store as s; "
                  "s.PRIVATE_DIR=Path(os.environ['TEST_PRIVATE_DIR']); "
                  "[s.update_user(os.environ['TEST_TOKEN'],timer_action='switch') for _ in range(8)]")
        processes = [subprocess.Popen([sys.executable, '-c', script], env=env) for _ in range(2)]
        for process in processes:
            self.assertEqual(process.wait(timeout=30), 0)
        result = store.read_user(self.alpha)
        self.assertEqual(result['revision'], started['revision'] + 16)
        self.assertEqual(result['timer']['mode'], 'Study')
        # A new process can read the same account and saved timer.
        script = ("import os; from pathlib import Path; import studyflow_store as s; "
                  "s.PRIVATE_DIR=Path(os.environ['TEST_PRIVATE_DIR']); "
                  "assert s.read_user(os.environ['TEST_TOKEN'])['timer']['total']==1500")
        subprocess.run([sys.executable, '-c', script], env=env, check=True, timeout=30)

    def test_legacy_shared_records_are_not_imported_or_modified(self):
        legacy = Path(self.folder.name) / 'studyflow.json'
        legacy.write_text(json.dumps([sample_subject()]), encoding='utf-8')
        before = legacy.read_bytes()
        token = store.authenticate('third_user', PASSWORD, 'third-ip', signup=True)
        self.assertEqual(store.read_user(token)['subjects'], [])
        self.assertEqual(legacy.read_bytes(), before)


class PlanningTests(unittest.TestCase):
    def test_duration_examples_and_edges(self):
        for hours, expected in [(0.3, '18 min'), (0.5, '30 min'), (1, '1 hr'),
                                (1.5, '1 hr 30 min'), (2.7, '2 hrs 42 min'),
                                (0, '0 min'), (0.001, '1 min'), (1.999, '2 hrs')]:
            with self.subTest(hours=hours):
                self.assertEqual(main.format_duration(hours), expected)

    def test_invalid_durations(self):
        for hours in (-1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                main.format_duration(hours)

    def test_difficulty_factors_minimum_and_unrounded_workload(self):
        subject = sample_subject()
        for difficulty, factor in [('Easy', 1), ('Medium', 1.15), ('Hard', 1.3)]:
            subject['difficulty'] = difficulty
            self.assertAlmostEqual(main.recommended_hours(subject), 6 * factor / 3)
        subject['exam_date'] = date.today().isoformat()
        subject['chapters'] = [{'hours': 0.001, 'completed': False}]
        self.assertGreater(main.recommended_hours(subject), 0)
        self.assertEqual(main.format_duration(main.recommended_hours(subject)), '1 min')
        subject['exam_date'] = (date.today() + timedelta(days=30)).isoformat()
        self.assertEqual(main.recommended_hours(subject), 0.1)

    def test_no_rounding_before_total_or_allocation(self):
        subject = sample_subject()
        subject['exam_date'] = (date.today() + timedelta(days=7)).isoformat()
        expected = 6 * 1.3 / 7
        self.assertAlmostEqual(main.recommended_hours(subject), expected)
        self.assertNotEqual(main.recommended_hours(subject), round(expected, 1))


class WorkloadTests(unittest.TestCase):
    def subject(self, hours, days=1, difficulty='Easy', name='Subject'):
        subject = sample_subject()
        subject.update(name=name, difficulty=difficulty,
                       exam_date=(date.today() + timedelta(days=days)).isoformat(),
                       chapters=[{'name': 'Chapter', 'hours': hours, 'completed': False}])
        return subject

    def test_tomorrow_seven_hours_with_six_available(self):
        result = main.analyze_workload([self.subject(7)], 6)
        self.assertEqual(result['summary']['required'], 7)
        self.assertEqual(result['summary']['available'], 6)
        self.assertEqual(result['extra_needed'], 1)
        self.assertEqual(result['allocated_today'], 6)
        self.assertEqual(result['urgent']['days'], 1)

    def test_actual_workload_is_separate_from_difficulty_adjustment(self):
        result = main.analyze_workload([self.subject(7, difficulty='Hard')], 6)
        self.assertAlmostEqual(result['recommended_today'], 9.1)
        self.assertEqual(result['summary']['required'], 7)
        self.assertEqual(result['extra_needed'], 1)
        self.assertEqual(result['allocated_today'], 6)

    def test_same_deadline_shares_capacity_once(self):
        result = main.analyze_workload([self.subject(4), self.subject(4, difficulty='Hard')], 6)
        self.assertEqual(len(result['deadlines']), 1)
        self.assertEqual(result['summary']['required'], 8)
        self.assertEqual(result['summary']['available'], 6)
        self.assertEqual(result['extra_needed'], 2)
        self.assertEqual([row['allocated'] for row in result['rows']], [4, 2])

    def test_staggered_deadlines_do_not_add_overlapping_deficits(self):
        result = main.analyze_workload([self.subject(7, days=1), self.subject(8, days=2)], 6)
        self.assertEqual([point['extra'] for point in result['deadlines']], [1, 3])
        self.assertEqual(result['extra_needed'], 3)  # The earlier extra hour is part of these three.
        self.assertEqual(result['urgent']['extra'], 1)
        self.assertEqual(result['summary']['available'], 12)
        self.assertEqual(result['summary']['required'], 15)

    def test_later_spare_time_cannot_fix_an_earlier_exam(self):
        result = main.analyze_workload([self.subject(1, days=10), self.subject(7, days=1)], 6)
        self.assertEqual(result['extra_needed'], 1)
        self.assertEqual(result['summary']['days'], 1)
        self.assertEqual(result['allocated_today'], 6)

    def test_sufficient_time_across_deadlines(self):
        result = main.analyze_workload([self.subject(3, days=1), self.subject(9, days=2)], 6)
        self.assertEqual(result['extra_needed'], 0)
        self.assertIsNone(result['urgent'])
        self.assertEqual(result['summary']['required'], 12)
        self.assertEqual(result['summary']['available'], 12)
        self.assertEqual(result['allocated_today'], 6)

    def test_completed_chapters_are_excluded(self):
        subject = self.subject(4)
        subject['chapters'].append({'name': 'Finished', 'hours': 10, 'completed': True})
        result = main.analyze_workload([subject], 6)
        self.assertEqual(result['summary']['required'], 4)
        self.assertEqual(result['extra_needed'], 0)

    def test_today_and_overdue_exams_have_no_available_study_days(self):
        for days in (0, -1):
            with self.subTest(days=days):
                result = main.analyze_workload([self.subject(3, days=days)], 6)
                self.assertEqual(result['summary']['available'], 0)
                self.assertEqual(result['extra_needed'], 3)
                self.assertEqual(result['allocated_today'], 0)
                self.assertEqual(result['recommended_today'], 0)

    def test_exam_today_does_not_use_time_needed_for_future_subjects(self):
        result = main.analyze_workload([self.subject(3, days=0), self.subject(6, days=1)], 6)
        self.assertEqual([row['allocated'] for row in result['rows']], [0, 6])
        self.assertEqual(result['allocated_today'], 6)
        self.assertEqual(result['extra_needed'], 3)

    def test_zero_workload_and_completed_subjects(self):
        completed = self.subject(5)
        completed['chapters'][0]['completed'] = True
        for subjects in ([], [self.subject(0)], [completed]):
            with self.subTest(subjects=subjects):
                result = main.analyze_workload(subjects, 6)
                self.assertEqual(result['rows'], [])
                self.assertIsNone(result['summary'])
                self.assertEqual(result['extra_needed'], 0)
                self.assertEqual(result['allocated_today'], 0)

    def test_fractional_workloads_and_small_positive_shortfalls(self):
        result = main.analyze_workload([self.subject(2.7), self.subject(3.55)], 6)
        self.assertAlmostEqual(result['extra_needed'], 0.25)
        self.assertEqual(main.format_duration(result['extra_needed']), '15 min')
        tiny = main.analyze_workload([self.subject(0.001)], 0)
        self.assertEqual(main.format_duration(tiny['extra_needed']), '1 min')

    def test_floating_point_noise_is_not_reported_as_extra_work(self):
        result = main.analyze_workload([self.subject(0.1), self.subject(0.2)], 0.3)
        self.assertEqual(result['extra_needed'], 0)

    def test_allocation_never_exceeds_daily_budget_or_remaining_work(self):
        subjects = [self.subject(0.1), self.subject(0.2), self.subject(0.7),
                    self.subject(0.001, days=2, difficulty='Hard'), self.subject(20, days=3)]
        for daily in (0, 0.3, 0.5, 0.75, 1, 2.7, 6):
            with self.subTest(daily=daily):
                result = main.analyze_workload(subjects, daily)
                self.assertLessEqual(math.fsum(row['allocated'] for row in result['rows']), daily)
                for row in result['rows']:
                    self.assertGreaterEqual(row['allocated'], 0)
                    self.assertLessEqual(row['allocated'], row['remaining'])
                    self.assertLessEqual(row['allocated'], row['recommended'])

    def test_priority_is_nearest_exam_then_difficulty(self):
        subjects = [self.subject(4, days=3, difficulty='Hard', name='Later'),
                    self.subject(2, name='Easy'), self.subject(2, difficulty='Hard', name='Hard')]
        result = main.analyze_workload(subjects, 3)
        self.assertEqual([row['subject']['name'] for row in result['rows']], ['Hard', 'Easy', 'Later'])
        self.assertEqual([row['allocated'] for row in result['rows']], [2, 1, 0])

    def test_recalculates_changes_without_mutating_subjects(self):
        subject = self.subject(7)
        before = copy.deepcopy(subject)
        self.assertEqual(main.analyze_workload([subject], 6)['extra_needed'], 1)
        self.assertEqual(subject, before)
        self.assertEqual(main.analyze_workload([subject], 7)['extra_needed'], 0)
        subject['exam_date'] = (date.today() + timedelta(days=2)).isoformat()
        self.assertEqual(main.analyze_workload([subject], 6)['extra_needed'], 0)
        subject['chapters'][0]['hours'] = 13
        self.assertEqual(main.analyze_workload([subject], 6)['extra_needed'], 1)
        subject['chapters'][0]['completed'] = True
        self.assertEqual(main.analyze_workload([subject], 6)['extra_needed'], 0)

    def test_invalid_daily_hours_are_rejected(self):
        for daily in (-1, float('inf'), float('nan')):
            with self.assertRaises(ValueError):
                main.analyze_workload([self.subject(1)], daily)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = TemporaryDirectory()
        cls.secret = secrets.token_urlsafe(48)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            cls.port = listener.getsockname()[1]
        cls.url = f'http://127.0.0.1:{cls.port}'
        cls.env = os.environ.copy()
        cls.env.update(PORT=str(cls.port), STUDYFLOW_SESSION_SECRET=cls.secret,
                       RAILWAY_VOLUME_MOUNT_PATH=cls.folder.name)
        cls.log = open(Path(cls.folder.name) / 'server.log', 'w', encoding='utf-8')
        cls.server = subprocess.Popen([sys.executable, 'main.py'], env=cls.env,
                                      stdout=cls.log, stderr=cls.log)
        for _ in range(200):
            try:
                with urllib.request.urlopen(cls.url + '/login', timeout=1):
                    pass
                break
            except (OSError, urllib.error.URLError):
                if cls.server.poll() is not None:
                    raise RuntimeError('Test server exited; inspect ' + cls.log.name)
                time.sleep(0.1)
        else:
            cls.tearDownClass()
            raise RuntimeError('Test server did not start')

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=15)
        cls.log.close()
        cls.folder.cleanup()

    def browser(self):
        # The test uses HTTP loopback, while exercising Railway's Secure cookie setting.
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('https', 'http'))
        jar = http.cookiejar.CookieJar(policy)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None

        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())
        return opener, jar

    def request(self, browser, path, data=None):
        encoded = urllib.parse.urlencode(data).encode() if data is not None else None
        try:
            response = browser[0].open(self.url + path, encoded, timeout=10)
        except urllib.error.HTTPError as response:
            # Python clears the exception variable after this block.
            result = response
        else:
            result = response
        try:
            return SimpleNamespace(status=result.status, headers=result.headers, body=result.read())
        finally:
            result.close()

    def session(self, browser):
        cookie = next(cookie for cookie in browser[1] if cookie.name == 'studyflow_session')
        payload = TimestampSigner(self.secret).unsign(cookie.value.encode())
        return json.loads(base64.b64decode(payload))

    def signup(self, username):
        browser = self.browser()
        self.assertEqual(self.request(browser, '/signup').status, 200)
        result = self.request(browser, '/auth/signup', {'username': username, 'password': PASSWORD,
                              'csrf_token': self.session(browser)['csrf']})
        self.assertEqual((result.status, result.headers['Location']), (303, '/'))
        return browser

    def test_dashboard_redirects_anonymous_visitors(self):
        response = self.request(self.browser(), '/')
        self.assertEqual((response.status, response.headers['Location']), (307, '/login'))

    def test_csrf_and_cookie_security(self):
        browser = self.browser()
        response = self.request(browser, '/signup')
        cookie = response.headers['Set-Cookie'].lower()
        for flag in ('httponly', 'samesite=lax', 'secure'):
            self.assertIn(flag, cookie)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        result = self.request(browser, '/auth/signup', {'username': 'csrf_user', 'password': PASSWORD,
                                                        'csrf_token': 'forged'})
        self.assertEqual(result.status, 403)

    def test_logout_revokes_a_copied_cookie_and_requires_post(self):
        browser = self.signup('logout_student')
        copied = self.browser()
        for cookie in browser[1]:
            copied[1].set_cookie(copy.copy(cookie))
        self.assertEqual(self.request(browser, '/').status, 200)
        self.assertNotEqual(self.request(browser, '/auth/logout').status, 200)
        response = self.request(browser, '/auth/logout', {'csrf_token': self.session(browser)['csrf']})
        self.assertEqual(response.status, 303)
        self.assertEqual(self.request(copied, '/').headers['Location'], '/login')

    def test_two_accounts_and_new_device_login(self):
        first, second = self.signup('http_alpha'), self.signup('http_beta')
        token_a, token_b = self.session(first)['token'], self.session(second)['token']
        private = Path(self.folder.name) / 'studyflow_private'
        with patch.object(store, 'PRIVATE_DIR', private):
            store.update_user(token_a, {'subjects': [sample_subject()]})
            self.assertEqual(store.read_user(token_b)['subjects'], [])
        device = self.browser()
        self.request(device, '/login')
        self.request(device, '/auth/login', {'username': 'HTTP_ALPHA', 'password': PASSWORD,
                                            'csrf_token': self.session(device)['csrf']})
        self.assertIn('Algorithms', self.request(device, '/').body.decode())
        self.assertNotIn('Algorithms', self.request(second, '/').body.decode())
        # User IDs and filenames supplied by a visitor do not select another user's data.
        self.assertNotIn('Algorithms', self.request(second, '/?user_id=http_alpha').body.decode())

    def test_workload_summary_recalculates_saved_data(self):
        browser = self.signup('workload_student')
        token = self.session(browser)['token']
        subject = sample_subject()
        subject.update(difficulty='Easy', exam_date=(date.today() + timedelta(days=1)).isoformat(),
                       chapters=[{'name': 'Graphs', 'hours': 7, 'completed': False}])
        with patch.object(store, 'PRIVATE_DIR', Path(self.folder.name) / 'studyflow_private'):
            store.update_user(token, {'subjects': [subject], 'settings':
                              {'daily_hours': 6, 'study_minutes': 25, 'break_minutes': 5}})
        page = self.request(browser, '/').body.decode()
        self.assertIn('Consider adding 1 extra hour today.', page)
        self.assertIn('Extra needed', page)
        self.assertIn('Allocated today: 6 hrs', page)
        with patch.object(store, 'PRIVATE_DIR', Path(self.folder.name) / 'studyflow_private'):
            store.update_user(token, {'settings': {'daily_hours': 7, 'study_minutes': 25, 'break_minutes': 5}})
        self.assertIn('Your remaining workload fits before these exams.', self.request(browser, '/').body.decode())
        subject['exam_date'] = date.today().isoformat()
        with patch.object(store, 'PRIVATE_DIR', Path(self.folder.name) / 'studyflow_private'):
            store.update_user(token, {'subjects': [subject]})
        page = self.request(browser, '/').body.decode()
        self.assertIn('Allocated today: 0 min', page)
        self.assertIn('No study days before exam', page)
        subject['chapters'][0]['completed'] = True
        with patch.object(store, 'PRIVATE_DIR', Path(self.folder.name) / 'studyflow_private'):
            store.update_user(token, {'subjects': [subject]})
        self.assertIn('Add chapters to generate your study plan.', self.request(browser, '/').body.decode())

    def test_login_rate_limit_over_http(self):
        browser = self.signup('limited_student')
        self.request(browser, '/auth/logout', {'csrf_token': self.session(browser)['csrf']})
        self.request(browser, '/login')
        form = {'username': 'limited_student', 'password': 'Wrong-password-123',
                'csrf_token': self.session(browser)['csrf']}
        for _ in range(5):
            self.assertIn('error=invalid', self.request(browser, '/auth/login', form).headers['Location'])
        response = self.request(browser, '/auth/login', form)
        self.assertIn('error=limited', response.headers['Location'])
        self.assertEqual(response.headers['Retry-After'], '900')

    def test_bounded_forms_and_unicode_csrf_are_rejected(self):
        browser = self.browser()
        self.request(browser, '/login')
        self.assertEqual(self.request(browser, '/auth/login', {'username': 'x' * 5000}).status, 413)
        self.assertEqual(self.request(browser, '/auth/login', {'csrf_token': '\u2603'}).status, 403)
        self.assertEqual(self.request(self.browser(), '/auth/signup', {
            'username': 'no_session', 'password': PASSWORD, 'csrf_token': 'missing'}).status, 403)

    def test_server_restart_preserves_login_data_and_running_timer(self):
        browser = self.signup('restart_student')
        token = self.session(browser)['token']
        with patch.object(store, 'PRIVATE_DIR', Path(self.folder.name) / 'studyflow_private'):
            saved = store.update_user(token, {'subjects': [sample_subject()]}, timer_action='start')
        self.server.terminate()
        self.server.wait(timeout=15)
        type(self).server = subprocess.Popen([sys.executable, 'main.py'], env=self.env,
                                            stdout=self.log, stderr=self.log)
        for _ in range(200):
            try:
                response = self.request(browser, '/')
                if response.status == 200:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            self.fail('Restarted server was not ready')
        self.assertIn('Algorithms', response.body.decode())
        with patch.object(store, 'PRIVATE_DIR', Path(self.folder.name) / 'studyflow_private'):
            restored = store.read_user(token)
        self.assertEqual(restored['timer']['deadline'], saved['timer']['deadline'])
        self.assertTrue(restored['timer']['running'])

    def test_private_files_and_legacy_json_are_not_web_routes(self):
        for path in ('/studyflow.json', '/study_sessions.json',
                     '/studyflow_private/accounts.json', '/studyflow_private/users/test.json'):
            self.assertEqual(self.request(self.browser(), path).status, 404)

    def test_tampered_cookie_cannot_open_dashboard(self):
        browser = self.signup('tamper_student')
        for cookie in browser[1]:
            payload, signature = cookie.value.rsplit('.', 1)
            # Change a significant signature byte, avoiding unused base64 padding bits.
            signature = ('A' if signature[0] != 'A' else 'B') + signature[1:]
            cookie.value = payload + '.' + signature
        self.assertEqual(self.request(browser, '/').headers['Location'], '/login')


if __name__ == '__main__':
    unittest.main()
