"""Smoke test script for AtendeXportal PoC.
- Logs in as lecturer, creates a session, logs in as student, marks attendance.
- Uses requests.Session to preserve cookies.
"""
import requests
from pprint import pprint

BASE = 'http://127.0.0.1:5000'

def lecturer_flow():
    s = requests.Session()
    # login lecturer
    r = s.post(f'{BASE}/login/lecturer', data={'username':'lecturer1','password':'password'})
    print('Lecturer login status:', r.status_code)
    print('Lecturer login response text snippet:', r.text[:200])
    # create session
    r = s.post(f'{BASE}/session/create', data={'course_name':'Test 101','duration':1,'grace':1,'latitude':6.317, 'longitude':5.631, 'radius':10})
    print('Create session status:', r.status_code)
    print('Create session response snippet:', r.text[:200])
    # get lecturer page to find the token
    r = s.get(f'{BASE}/lecturer')
    if r.ok:
        txt = r.text
        # crude parse for token
        import re
        m = re.search(r'Token: <code>([A-Za-z0-9]+)</code>', txt)
        token = m.group(1) if m else None
        print('Found token:', token)
        return token
    return None

def student_flow(token):
    s = requests.Session()
    r = s.post(f'{BASE}/login/student', data={'ub_id':'UB1001','password':'password'})
    print('Student login status:', r.status_code)
    # mark attendance with lat/lon near the classroom to be within radius
    payload = {'token': token, 'lat': 6.317, 'lon': 5.631}
    r = s.post(f'{BASE}/session/mark', json=payload)
    print('Mark attendance status:', r.status_code)
    try:
        pprint(r.json())
    except Exception:
        print('No JSON response')

if __name__ == '__main__':
    tk = lecturer_flow()
    if tk:
        student_flow(tk)
    else:
        print('Could not find session token; check server logs.')
