
from nicegui import ui
from datetime import date
from pathlib import Path
import json
import time
import os

ui.page_title('StudyFlow')
DATA_FILE = Path('studyflow.json')
SESSIONS_FILE = Path('study_sessions.json')
COLORS = ['#8B5CF6', '#3B82F6', '#06B6D4', '#10B981',
          '#F59E0B', '#EC4899', '#EF4444', '#6366F1']


def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default


subjects = read_json(DATA_FILE, [])
if not isinstance(subjects, list):
    subjects = []
for subject in subjects:
    subject.setdefault('chapters', [])

sessions = read_json(SESSIONS_FILE, {})
if not isinstance(sessions, dict):
    sessions = {}

selected_subject = None
opened_subject = [None]


def save_data():
    DATA_FILE.write_text(json.dumps(subjects, ensure_ascii=False, indent=2), encoding='utf-8')


def save_sessions():
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2), encoding='utf-8')


def today_sessions():
    today = date.today().isoformat()
    if sessions.get('date') != today:
        sessions.update(date=today, completed=0)
        save_sessions()
    return sessions['completed']


def notice(message, icon='check_circle'):
    ui.notify(message, position='bottom', timeout=2500,
              color='#292342', text_color='white', icon=icon)


ui.dark_mode().enable()
ui.add_head_html('''
<style>
body {background:radial-gradient(ellipse at top left,#231744,#11162a 48%,#090d18);
      color:#f4f2ff;min-height:100vh}
.glass {background:#191d32!important;border:1px solid #343650;
        border-radius:18px!important}
.subject-expansion {background:#191d32!important;border:1px solid #343650;
        border-radius:15px!important;overflow:hidden}
.subject-expansion .q-item {min-height:64px}
.subject-expansion .q-expansion-item__content {padding:0 14px 14px}
.add-subject-btn {
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
.focus-primary {background:#793dc0!important;color:white!important;
    border-radius:12px!important;box-shadow:none!important;
    font-weight:600;padding:9px 22px!important}
.focus-primary:hover {background:#8950cc!important}
.focus-secondary {background:#29243e!important;border:1px solid #4b4269!important;
    border-radius:12px!important;color:#e2d5ff!important}
.focus-badge {background:#2a2442;border:1px solid #403659;border-radius:99px;
    padding:7px 14px;color:#d6c5fb}
.focus-ring .q-circular-progress__circle {stroke-linecap:round}
.celebrate {font-size:70px;animation:pop .9s infinite alternate}
@keyframes pop {from{transform:scale(.9)}to{transform:scale(1.13)}}
</style>
''')


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
    if exam_date.value < date.today().isoformat():
        notice('Exam date cannot be in the past', 'warning')
        return
    subjects.append({'name': name, 'difficulty': difficulty.value,
                     'exam_date': exam_date.value, 'color': subject_color.value,
                     'chapters': []})
    save_data()
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
    save_data()
    refresh_all()
    notice('Subject deleted', 'delete_outline')


def open_chapter_dialog(subject):
    global selected_subject
    selected_subject = subject
    chapter_name.value = ''
    chapter_hours.value = 1
    chapter_dialog.open()


def save_chapter():
    name = (chapter_name.value or '').strip()
    if not name or chapter_hours.value is None or chapter_hours.value <= 0:
        notice('Enter a name and valid study hours', 'warning')
        return
    selected_subject['chapters'].append({
        'name': name, 'hours': float(chapter_hours.value), 'completed': False
    })
    opened_subject[0] = selected_subject
    save_data()
    refresh_all()
    chapter_dialog.close()
    notice('Chapter added')


def toggle_chapter(subject, chapter, completed):
    was_complete = progress(subject) == 100
    chapter['completed'] = completed
    opened_subject[0] = subject
    save_data()
    refresh_all()
    if completed and progress(subject) == 100 and not was_complete:
        celebration_name.set_text(subject['name'])
        celebration_dialog.open()
    elif completed:
        notice(f'{chapter["name"]} completed')


def delete_chapter(subject, chapter):
    opened_subject[0] = subject
    subject['chapters'].remove(chapter)
    save_data()
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
                .props('round unelevated').style(
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
                    ui.label(f'{remaining_hours(subject):g}h remaining') \
                        .classes('text-xs text-gray-400')
                if remaining_hours(subject):
                    if remaining_days(subject) == 0:
                        ui.label('Exam is today or overdue').classes('text-xs text-red-400')
                    else:
                        ui.label(f'Suggested: {recommended_hours(subject):g}h/day') \
                            .classes('text-xs text-purple-300')
                        if recommended_hours(subject) > float(daily_hours.value or 0):
                            ui.label('Study workload may be too high') \
                                .classes('text-xs text-orange-400')
                for chapter in chapters:
                    with ui.row().classes('w-full items-center gap-2 flex-nowrap'):
                        ui.checkbox(value=chapter['completed'],
                            on_change=lambda e, s=subject, c=chapter:
                                toggle_chapter(s, c, e.value)).props('dense color=purple')
                        with ui.column().classes('gap-0 flex-1 min-w-0'):
                            ui.label(chapter['name']).classes('text-sm break-words').style(
                                'text-decoration:line-through;opacity:.6' if chapter['completed'] else '')
                            ui.label(f'{chapter["hours"]:g}h').classes('text-xs text-gray-400')
                        ui.button(icon='delete_outline',
                            on_click=lambda s=subject, c=chapter: delete_chapter(s, c)) \
                            .props('flat round dense color=grey')
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
    pending = [s for s in subjects if remaining_hours(s) > 0]
    if not pending:
        ui.label('Add chapters to generate your study plan.').classes('text-gray-400')
        return
    pending.sort(key=lambda s: (
        remaining_days(s),
        -{'Easy': 1, 'Medium': 2, 'Hard': 3}.get(s['difficulty'], 2)
    ))
    available = float(daily_hours.value or 0)
    total = sum(recommended_hours(s) for s in pending)
    with ui.card().classes('glass w-full p-4 gap-2'):
        ui.label(f'Recommended workload: {total:.1f}h/day').classes('font-bold')
        if total > available:
            ui.label('Your available study hours may not be enough.') \
                .classes('text-orange-400 text-sm')
        for subject in pending:
            allocated = min(available, recommended_hours(subject))
            with ui.row().classes('w-full justify-between'):
                ui.label(subject['name']).classes('text-sm')
                ui.label(f'{allocated:.1f}h today').classes('text-sm text-purple-300')
            available = max(0, available - allocated)


with ui.dialog() as color_dialog, ui.card().classes('glass w-full max-w-sm'):
    ui.label('Custom Color').classes('text-lg font-bold')
    custom_color = ui.color_input(value=COLORS[0])
    ui.button('Apply Color', on_click=apply_custom_color).classes('w-full')

with ui.dialog() as subject_dialog, ui.card().classes(
    'glass w-full max-w-sm max-h-[90vh] overflow-y-auto'):
    ui.label('Add New Subject').classes('text-xl font-bold')
    subject_name = ui.input('Subject Name').classes('w-full')
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
    ui.label('Subject Color').classes('text-sm text-gray-400')
    subject_color = ui.input(value=COLORS[0]).classes('hidden')
    show_colors()
    ui.button('Custom Color', icon='palette', on_click=color_dialog.open).props('outline')
    ui.button('Save Subject', on_click=save_subject).classes('w-full')

with ui.dialog() as chapter_dialog, ui.card().classes('glass w-full max-w-sm'):
    ui.label('Add Chapter').classes('text-xl font-bold')
    chapter_name = ui.input('Chapter Name').classes('w-full')
    chapter_hours = ui.number('Estimated Study Hours', value=1, min=0.5, step=0.5) \
        .classes('w-full')
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
        ui.button('Add Subject', icon='add', on_click=open_subject_dialog) \
            .props('unelevated no-caps').classes('add-subject-btn')

    show_dashboard()

    with ui.row().classes('w-full items-center gap-3 flex-wrap'):
        ui.label('Available study hours per day').classes('text-sm')
        daily_hours = ui.number(value=3, min=0.5, max=24, step=0.5).classes('w-24')
        daily_hours.on('update:model-value', lambda: refresh_all())

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
                ).props('flat round dense color=purple').tooltip('Expand / Minimize')
                ui.button(
                    icon='tune',
                    on_click=lambda: settings_panel.set_visibility(not settings_panel.visible)
                ).props('flat round dense color=purple').tooltip('Timer Settings')
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
            study_minutes = ui.number('Focus minutes', value=25, min=1, max=240) \
                .classes('w-32')
            break_minutes = ui.number('Break minutes', value=5, min=1, max=120) \
                .classes('w-32')
        settings_panel.set_visibility(False)

        timer_state = {'remaining': 25 * 60, 'total': 25 * 60,
                       'running': False, 'mode': 'Study', 'deadline': None}

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

        def start_timer():
            if not timer_state['running']:
                if timer_state['remaining'] == timer_state['total']:
                    minutes = study_minutes.value if timer_state['mode'] == 'Study' else break_minutes.value
                    timer_state['remaining'] = timer_state['total'] = int(minutes or 1) * 60
                    update_timer_display()
                timer_state['deadline'] = time.monotonic() + timer_state['remaining']
                timer_state['running'] = True
            if not expanded[0]:
                toggle_focus_size()
            start_button.set_text('Focusing...' if timer_state['mode'] == 'Study' else 'On Break...')
            start_button.props('icon=check')

        def pause_timer():
            if timer_state['running']:
                timer_state['remaining'] = max(
                    0, int(timer_state['deadline'] - time.monotonic() + 0.999)
                )
                timer_state['running'] = False
                update_timer_display()
                start_button.set_text('Resume Focus' if timer_state['mode'] == 'Study' else 'Resume Break')
                start_button.props('icon=play_arrow')

        def reset_timer():
            timer_state['running'] = False
            timer_state['mode'] = 'Study'
            seconds = int(study_minutes.value or 25) * 60
            timer_state.update(remaining=seconds, total=seconds)
            update_timer_display()
            start_button.set_text('Start Focus')
            start_button.props('icon=play_arrow')

        def switch_mode():
            timer_state['running'] = False
            timer_state['mode'] = 'Break' if timer_state['mode'] == 'Study' else 'Study'
            minutes = break_minutes.value if timer_state['mode'] == 'Break' \
                else study_minutes.value
            seconds = int(minutes or 1) * 60
            timer_state.update(remaining=seconds, total=seconds)
            update_timer_display()
            start_button.set_text('Start Focus' if timer_state['mode'] == 'Study' else 'Start Break')
            start_button.props('icon=play_arrow')

        with ui.row().classes('gap-3 flex-nowrap items-center justify-center w-full'):
            ui.button(icon='restart_alt', on_click=reset_timer) \
                .props('flat round').classes('focus-secondary').tooltip('Reset')
            pause_button = ui.button(icon='pause', on_click=pause_timer) \
                .props('flat round').classes('focus-secondary').tooltip('Pause')
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
            update_sessions()
            if not timer_state['running']:
                return
            timer_state['remaining'] = max(
                0, int(timer_state['deadline'] - time.monotonic() + 0.999)
            )
            if timer_state['remaining'] == 0:
                timer_state['running'] = False
                if timer_state['mode'] == 'Study':
                    today_sessions()
                    sessions['completed'] += 1
                    save_sessions()
                    update_sessions()
                    notice('Focus session completed!')
                else:
                    notice('Break finished. Ready to focus?', 'timer')
                switch_mode()
            else:
                update_timer_display()

        ui.timer(1, tick)


ui.run(
    host='0.0.0.0',
    port=int(os.environ.get('PORT', 8080)),
    reload=False
)
