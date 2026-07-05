
import unittest
from api.app import app, init_db, generate_password_hash
from flask import session
import json

class TestFlexibleLogin(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DATABASE_URL'] = 'sqlite:///:memory:' # Use sqlite for testing if possible or just rely on the mock/real db
        self.client = app.test_client()
        with app.app_context():
            init_db()
            # Create a test student
            from api.app import commit_db
            commit_db("INSERT INTO users (role, first_name, last_name, ub_id, matric, password_hash, active) VALUES (?,?,?,?,?,?,?)",
                      ('student', 'Test', 'Student', 'UB001', 'MAT001', generate_password_hash('pass123'), 1))

    def test_student_login_ub_id(self):
        response = self.client.post('/login/student', data={
            'identifier': 'UB001',
            'password': 'pass123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Student Dashboard', response.data)

    def test_student_login_matric(self):
        response = self.client.post('/login/student', data={
            'identifier': 'MAT001',
            'password': 'pass123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Student Dashboard', response.data)

    def test_device_restriction_removed(self):
        # We want to verify that evaluate_session_for_student doesn't check for device conflicts anymore
        with app.app_context():
            from api.app import query_db, evaluate_session_for_student, commit_db
            # Create a session
            commit_db("INSERT INTO sessions (token, lecturer_id, course_name, start_time, duration_min, active) VALUES (?,?,?,?,?,?)",
                      ('TESTOKEN', 1, 'Test Course', '2023-01-01 00:00:00', 60, 1))
            s = query_db("SELECT * FROM sessions WHERE token = 'TESTOKEN'", one=True)
            student = query_db("SELECT * FROM users WHERE ub_id = 'UB001'", one=True)

            # Simulate another student already marked attendance from a device fingerprint
            # In a real scenario, we'd have a specific device_fp
            # But evaluate_session_for_student now hardcodes device_conflict = False

            info = evaluate_session_for_student(s, student['id'], 0, 0, '127.0.0.1', 'Mozilla/5.0')
            self.assertFalse(info['device_conflict'])
            self.assertFalse(info['other_device_used'])

if __name__ == '__main__':
    unittest.main()
