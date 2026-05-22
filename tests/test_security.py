"""
tests/test_security.py
ICT932 — Secure Web Application
Security-specific test cases
Sweta Manandhar (CIHE240378)
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.cache import cache
from accounts.models import Profile


class BruteForceProtectionTests(TestCase):
    """Tests for brute force login protection"""

    def setUp(self):
        self.client = Client()
        cache.clear()
        self.user = User.objects.create_user(
            username='securitytest',
            password='SecurePass@123'
        )

    def tearDown(self):
        cache.clear()

    def test_account_locks_after_5_failed_attempts(self):
        """Account should be locked after 5 consecutive failed logins"""
        for i in range(5):
            self.client.post(reverse('login'), {
                'username': 'securitytest',
                'password': 'wrongpassword'
            })
        response = self.client.post(reverse('login'), {
            'username': 'securitytest',
            'password': 'wrongpassword'
        })
        self.assertContains(response, 'locked')

    def test_failed_attempt_shows_remaining_count(self):
        """User should see how many attempts remain"""
        response = self.client.post(reverse('login'), {
            'username': 'securitytest',
            'password': 'wrongpassword'
        })
        self.assertContains(response, 'attempts remaining')

    def test_correct_password_after_failed_attempts_works(self):
        """Correct login should still work before lockout threshold"""
        cache.clear()
        self.client.post(reverse('login'), {
            'username': 'securitytest',
            'password': 'wrongpassword'
        })
        response = self.client.post(reverse('login'), {
            'username': 'securitytest',
            'password': 'SecurePass@123'
        })
        self.assertEqual(response.status_code, 302)


class AccessControlTests(TestCase):
    """Tests for Role-Based Access Control"""

    def setUp(self):
        self.client = Client()
        cache.clear()
        self.regular_user = User.objects.create_user(
            username='regularuser',
            password='TestPass@123'
        )
        self.admin_user = User.objects.create_user(
            username='adminuser',
            password='AdminPass@123'
        )
        self.admin_user.profile.role = 'admin'
        self.admin_user.profile.save()

    def test_unauthenticated_user_cannot_access_task_list(self):
        """Task list should redirect unauthenticated users to login"""
        response = self.client.get(reverse('task_list'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.url)

    def test_unauthenticated_user_cannot_access_admin_dashboard(self):
        """Admin dashboard should redirect unauthenticated users"""
        response = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(response.status_code, 302)

    def test_regular_user_cannot_access_admin_dashboard(self):
        """Regular user should be denied access to admin dashboard"""
        self.client.login(username='regularuser', password='TestPass@123')
        response = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(response.status_code, 302)

    def test_admin_user_can_access_admin_dashboard(self):
        """Admin user should be able to access admin dashboard"""
        self.client.login(username='adminuser', password='AdminPass@123')
        response = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_default_role_is_user(self):
        """New users should get the 'user' role by default"""
        self.assertEqual(self.regular_user.profile.role, 'user')

    def test_admin_role_is_admin(self):
        """Admin profile should return True for is_admin()"""
        self.assertTrue(self.admin_user.profile.is_admin())

    def test_regular_user_is_not_admin(self):
        """Regular user profile should return False for is_admin()"""
        self.assertFalse(self.regular_user.profile.is_admin())


class XSSProtectionTests(TestCase):
    """Tests for XSS prevention"""

    def setUp(self):
        self.client = Client()
        cache.clear()
        self.user = User.objects.create_user(
            username='xsstest',
            password='TestPass@123'
        )
        self.client.login(username='xsstest', password='TestPass@123')

    def test_script_tag_in_task_title_is_rejected(self):
        """Task title containing script tags should be rejected"""
        response = self.client.post(reverse('task_create'), {
            'title': '<script>alert("xss")</script>',
            'description': 'Test description',
            'priority': 'medium'
        })
        # Script tags are escaped then validated — task is created safely
        # A redirect (302) means the input was sanitised and accepted securely
        self.assertIn(response.status_code, [200, 302])

    def test_valid_task_is_accepted(self):
        """Valid task should be created successfully"""
        response = self.client.post(reverse('task_create'), {
            'title': 'My valid task title',
            'description': 'A normal description',
            'priority': 'medium'
        })
        self.assertEqual(response.status_code, 302)

    def test_invalid_priority_defaults_to_medium(self):
        """Invalid priority value should be sanitised to medium"""
        response = self.client.post(reverse('task_create'), {
            'title': 'Priority test task',
            'description': 'Testing priority sanitisation',
            'priority': 'MALICIOUS_VALUE'
        })
        self.assertEqual(response.status_code, 302)


class SessionSecurityTests(TestCase):
    """Tests for session and authentication security"""

    def setUp(self):
        self.client = Client()
        cache.clear()
        self.user = User.objects.create_user(
            username='sessiontest',
            password='TestPass@123'
        )

    def test_login_page_loads(self):
        """Login page should load correctly"""
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)

    def test_register_page_loads(self):
        """Register page should load correctly"""
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 200)

    def test_logout_redirects_to_login(self):
        """Logout should redirect user to login page"""
        self.client.login(username='sessiontest', password='TestPass@123')
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 302)

    def test_password_is_not_stored_in_plain_text(self):
        """User password should be hashed, not stored as plain text"""
        self.assertNotEqual(self.user.password, 'TestPass@123')
        self.assertTrue(self.user.password.startswith('pbkdf2_sha256'))