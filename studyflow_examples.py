from datetime import date, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import timeit

# StudyFlow-inspired isolated examples; no changes to real study records.
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
    return max(0.1, round(hours / days, 1)) if days and hours else round(hours, 1)

def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default

subject = {'name': 'Algorithms', 'difficulty': 'Hard',
           'exam_date': (date.today() + timedelta(days=3)).isoformat(),
           'chapters': [{'hours': 3, 'completed': False},
                        {'hours': 3, 'completed': False}]}
print('Initial recommendation:', recommended_hours(subject))
assert recommended_hours(subject) == 2.6
alias = subject['chapters'][0]
alias['completed'] = True
print('Progress:', progress(subject))
assert progress(subject) == 50
print('Remaining hours:', remaining_hours(subject))
manual = 0
for chapter in subject['chapters']:
    if not chapter['completed']:
        manual += float(chapter['hours'])
assert manual == remaining_hours(subject) == 3
with TemporaryDirectory() as folder:
    path = Path(folder) / 'subject.json'
    path.write_text(json.dumps(subject, ensure_ascii=False, indent=2), encoding='utf-8')
    assert read_json(path, {}) == subject
    print('JSON round trip: OK')
    path.write_text('invalid json', encoding='utf-8')
    assert read_json(path, {}) == {}
    print('Invalid JSON fallback: OK')
try:
    print('3' + 2)
except TypeError:
    print('TypeError handled')
print('Precedence:', 2 + 3 * 4)
print('All assertions passed')
print('10000 calls, seconds:', min(timeit.repeat(lambda: remaining_hours(subject), number=10000, repeat=3)))
