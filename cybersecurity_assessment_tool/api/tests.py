from unittest.mock import patch

from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.core import mail

from api.models import Invitation, Organization, User, Report, Risk

class DatabaseEncryptionTests(TestCase):
    def setUp(self):
        # 1. Set up the prerequisite Foreign Keys needed for Reports and Risks
        self.org = Organization.objects.create(
            org_name="Wayne Enterprises",
            email_domain="wayne.com",
            website_domain="wayne.com",
            external_ip="198.51.100.14"
        )
        
        self.user = User.objects.create_user(
            first_name="Bruce",
            last_name="Wayne",
            email="bwayne@wayne.com",
            username="bwayne",
            password="securepassword123",
            organization=self.org
        )

    def test_report_json_decryption(self):
        """Test that EncryptedJSONField on the Report model encrypts/decrypts properly."""
        
        # 1. Define the plaintext JSON data
        plaintext_report_data = {
            "Overview": {
                "Primary Domain": "wayne.com",
                "External IP Address": "198.51.100.14"
            },
            "Vulnerabilities": {}
        }

        # 2. Save to the database (Django encrypts it into a gAAAAAB... string here)
        report = Report.objects.create(
            report_name="Q1 Security Audit",
            user_created=self.user,
            organization=self.org,
            report_text=plaintext_report_data
        )

        # 3. Fetch a fresh copy from the database (Django decrypts it back to JSON here)
        fetched_report = Report.objects.get(report_id=report.report_id)

        # 4. Assert the fetched dictionary matches our original plaintext dictionary
        self.assertEqual(fetched_report.report_text, plaintext_report_data)
        self.assertEqual(fetched_report.report_text["Overview"]["Primary Domain"], "wayne.com")

    def test_risk_fields_decryption(self):
        """Test that both EncryptedTextField and EncryptedJSONField on the Risk model work."""
        
        # 1. Create a prerequisite Report to attach the Risk to
        report = Report.objects.create(
            report_name="Penetration Test Results",
            user_created=self.user,
            organization=self.org,
        )

        # 2. Define the plaintext strings and JSON
        plaintext_overview = "An unpatched vulnerability was found on the main server."
        plaintext_affected = "Server 01, Server 02"
        plaintext_recommendations = {
            "easy_fix": "Apply the latest security patch.",
            "long_term_fix": "Implement automated patch management."
        }

        # 3. Save to the database
        risk = Risk.objects.create(
            risk_name="Unpatched Server Software",
            report=report,
            organization=self.org,
            overview=plaintext_overview,
            recommendations=plaintext_recommendations,
            severity="Critical",
            affected_elements=plaintext_affected
        )

        # 4. Fetch a fresh copy from the database
        fetched_risk = Risk.objects.get(risk_id=risk.risk_id)

        # 5. Assert the decrypted values match our original plaintext
        self.assertEqual(fetched_risk.overview, plaintext_overview)
        self.assertEqual(fetched_risk.affected_elements, plaintext_affected)
        self.assertEqual(fetched_risk.recommendations, plaintext_recommendations)
        self.assertEqual(fetched_risk.recommendations["easy_fix"], "Apply the latest security patch.")


@override_settings(
    GOOGLE_OAUTH_CLIENT_ID='test-google-client-id.apps.googleusercontent.com',
    STORAGES={
        'staticfiles': {
            'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage',
        },
    },
)
class PublicRegistrationGoogleButtonTests(TestCase):
    def test_google_oauth_start_redirects_to_google_consent_screen(self):
        response = self.client.get(
            reverse('google_oauth_start'),
            {'flow': 'registration', 'next': reverse('accounts:public_register')},
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn('https://accounts.google.com/o/oauth2/v2/auth', response.url)
        self.assertIn('client_id=test-google-client-id.apps.googleusercontent.com', response.url)
        self.assertEqual(self.client.session['google_oauth_flow'], 'registration')

    @override_settings(GOOGLE_OAUTH_CLIENT_SECRET='test-google-client-secret')
    @patch('api.views.urlopen')
    @patch('api.views.id_token.verify_oauth2_token')
    def test_google_oauth_callback_marks_registration_verified(self, mock_verify, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b'{"id_token": "fake-id-token"}'
        mock_verify.return_value = {
            'email': 'callback@example.com',
            'email_verified': True,
            'given_name': 'Callback',
            'family_name': 'User',
        }

        session = self.client.session
        session['google_oauth_state'] = 'state-123'
        session['google_oauth_flow'] = 'registration'
        session['google_oauth_next'] = reverse('accounts:public_register')
        session.save()

        response = self.client.get(
            reverse('google_oauth_callback'),
            {'code': 'sample-code', 'state': 'state-123'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('accounts:public_register'))
        self.assertEqual(self.client.session['verified_email'], 'callback@example.com')
        self.assertTrue(self.client.session['registration_verified_callback@example.com'])

    @override_settings(GOOGLE_OAUTH_CLIENT_SECRET='test-google-client-secret')
    @patch('api.views.urlopen')
    @patch('api.views.id_token.verify_oauth2_token')
    def test_google_oauth_callback_shows_expected_invite_email_on_mismatch(self, mock_verify, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b'{"id_token": "fake-id-token"}'
        mock_verify.return_value = {
            'email': 'wrong@example.com',
            'email_verified': True,
            'given_name': 'Wrong',
            'family_name': 'Account',
        }

        session = self.client.session
        session['google_oauth_state'] = 'invite-state-123'
        session['google_oauth_flow'] = 'invite'
        session['google_oauth_next'] = reverse('accounts:public_register')
        session['google_oauth_expected_email'] = 'invitee@example.com'
        session.save()

        response = self.client.get(
            reverse('google_oauth_callback'),
            {'code': 'sample-code', 'state': 'invite-state-123'},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            'Please use the Google account that matches the invited email address: invitee@example.com.',
            html=False,
        )

    def test_public_register_shows_google_button_when_client_id_present(self):
        response = self.client.get(reverse('accounts:public_register'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="googleSignupButton"', html=False)
        self.assertNotContains(response, 'Set GOOGLE_OAUTH_CLIENT_ID to enable Google sign-up')


@override_settings(
    GOOGLE_OAUTH_CLIENT_ID='test-google-client-id.apps.googleusercontent.com',
    GOOGLE_OAUTH_REQUIRE_OTP=True,
)
class GoogleOAuthLoginTests(TestCase):
    def test_public_register_shows_google_button_when_client_id_present(self):
        response = self.client.get(reverse('accounts:public_register'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="googleSignupButton"', html=False)
        self.assertNotContains(response, 'Set GOOGLE_OAUTH_CLIENT_ID to enable Google sign-up')


@override_settings(
    GOOGLE_OAUTH_CLIENT_ID='test-google-client-id.apps.googleusercontent.com',
    GOOGLE_OAUTH_REQUIRE_OTP=True,
)
class GoogleOAuthLoginTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(org_name="Acme School")
        self.user = User.objects.create_user(
            username="oauthuser",
            email="oauth@example.com",
            password="StrongPassword123!",
            organization=self.org,
            is_active=True,
        )

    @patch('api.views.id_token.verify_oauth2_token')
    def test_google_oauth_starts_otp_challenge_for_existing_active_user(self, mock_verify):
        mock_verify.return_value = {
            'email': self.user.email,
            'email_verified': True,
            'given_name': 'OAuth',
            'family_name': 'User',
        }

        response = self.client.post(
            reverse('google_oauth_login'),
            data='{"credential": "fake-google-jwt"}',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['success'], True)
        self.assertTrue(response.json()['requires_otp'])
        self.assertEqual(response.json()['email'], self.user.email)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertEqual(self.client.session['pending_user_id'], self.user.id)
        self.assertIn('login_otp', self.client.session)

    @override_settings(
        GOOGLE_OAUTH_CLIENT_ID='test-google-client-id.apps.googleusercontent.com',
        GOOGLE_OAUTH_REQUIRE_OTP=False,
    )
    @patch('api.views.id_token.verify_oauth2_token')
    def test_google_oauth_can_skip_otp_when_toggle_is_disabled(self, mock_verify):
        mock_verify.return_value = {
            'email': self.user.email,
            'email_verified': True,
        }

        response = self.client.post(
            reverse('google_oauth_login'),
            data='{"credential": "fake-google-jwt"}',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['success'], True)
        self.assertFalse(response.json().get('requires_otp', False))
        self.assertIn('_auth_user_id', self.client.session)

    @patch('api.views.id_token.verify_oauth2_token')
    def test_google_oauth_rejects_unknown_user(self, mock_verify):
        mock_verify.return_value = {
            'email': 'missing@example.com',
            'email_verified': True,
        }

        response = self.client.post(
            reverse('google_oauth_login'),
            data='{"credential": "fake-google-jwt"}',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['success'], False)


@override_settings(
    GOOGLE_OAUTH_CLIENT_ID='test-google-client-id.apps.googleusercontent.com',
    STORAGES={
        'staticfiles': {
            'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage',
        },
    },
)
class GoogleOAuthSignupTests(TestCase):
    @patch('api.views.id_token.verify_oauth2_token')
    def test_google_oauth_signup_marks_registration_email_verified(self, mock_verify):
        mock_verify.return_value = {
            'email': 'newsignup@example.com',
            'email_verified': True,
            'given_name': 'New',
            'family_name': 'User',
        }

        response = self.client.post(
            reverse('google_oauth_signup'),
            data='{"credential": "fake-google-jwt", "purpose": "registration"}',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['success'], True)
        self.assertEqual(response.json()['email'], 'newsignup@example.com')
        self.assertEqual(response.json()['first_name'], 'New')
        self.assertEqual(self.client.session['verified_email'], 'newsignup@example.com')
        self.assertTrue(self.client.session['registration_verified_newsignup@example.com'])

    def test_public_registration_prefills_google_verified_email_on_get(self):
        session = self.client.session
        session['verified_email'] = 'prefill@example.com'
        session['google_signup_verified_email'] = 'prefill@example.com'
        session['registration_verified_prefill@example.com'] = True
        session['google_signup_prefill'] = {
            'email': 'prefill@example.com',
            'first_name': 'Prefilled',
            'last_name': 'User',
        }
        session.save()

        response = self.client.get(reverse('accounts:public_register'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'value="prefill@example.com"', html=False)
        self.assertContains(response, 'password and OTP step can be skipped', html=False)

    @override_settings(
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
        DEFAULT_FROM_EMAIL='noreply@example.com',
        ADMIN_EMAIL_INBOX='admin@example.com',
        ASYNC_EMAIL_ENABLED=False,
    )
    def test_public_registration_sends_admin_notification_email(self):
        session = self.client.session
        session['verified_email'] = 'notify-admin@example.com'
        session['google_signup_verified_email'] = 'notify-admin@example.com'
        session['registration_verified_notify-admin@example.com'] = True
        session.save()

        response = self.client.post(
            reverse('accounts:public_register'),
            data={
                'first_name': 'Notify',
                'last_name': 'Admin',
                'username': 'notifyadmin',
                'company': 'Notify Org',
                'email': 'notify-admin@example.com',
                'password1': '',
                'password2': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('accounts:waiting'))
        self.assertGreaterEqual(len(mail.outbox), 2)
        self.assertIn('admin@example.com', mail.outbox[-1].to)
        self.assertEqual(mail.outbox[-1].subject, 'New Account Request - Action Required')

    @override_settings(
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
        DEFAULT_FROM_EMAIL='admin@example.com',
        ADMIN_EMAIL_INBOX='admin@example.com',
        ASYNC_EMAIL_ENABLED=False,
    )
    def test_public_registration_does_not_crash_when_admin_email_already_exists(self):
        User.objects.create_superuser(
            username='existingadmin',
            email='admin@example.com',
            password='StrongPassword123!',
        )

        session = self.client.session
        session['verified_email'] = 'new-org-admin@example.com'
        session['google_signup_verified_email'] = 'new-org-admin@example.com'
        session['registration_verified_new-org-admin@example.com'] = True
        session.save()

        response = self.client.post(
            reverse('accounts:public_register'),
            data={
                'first_name': 'New',
                'last_name': 'OrgAdmin',
                'username': 'neworgadmin',
                'company': 'Conflict Org',
                'email': 'new-org-admin@example.com',
                'password1': '',
                'password2': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('accounts:waiting'))
        self.assertTrue(User.objects.filter(username='neworgadmin').exists())

    def test_public_registration_can_skip_password_after_google_verification(self):
        session = self.client.session
        session['verified_email'] = 'google-admin@example.com'
        session['google_signup_verified_email'] = 'google-admin@example.com'
        session['registration_verified_google-admin@example.com'] = True
        session.save()

        response = self.client.post(
            reverse('accounts:public_register'),
            data={
                'first_name': 'Google',
                'last_name': 'Admin',
                'username': 'googleadmin',
                'company': 'Google Org',
                'email': 'google-admin@example.com',
                'password1': '',
                'password2': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('accounts:waiting'))

        user = User.objects.get(username='googleadmin')
        self.assertFalse(user.has_usable_password())

    def test_invite_signup_can_skip_password_after_google_verification(self):
        organization = Organization.objects.create(org_name='Invite Org')
        sender = User.objects.create_user(
            username='inviter',
            email='inviter@example.com',
            password='StrongPassword123!',
            organization=organization,
            is_active=True,
        )
        invitation = Invitation.objects.create(
            sender=sender,
            organization=organization,
            recipient_email='invitee@example.com',
            recipient_role='observer',
            status='sent',
        )

        session = self.client.session
        session['google_signup_verified_email'] = 'invitee@example.com'
        session.save()

        response = self.client.post(
            reverse('accounts:accept_invitation', args=[invitation.token]),
            data={
                'first_name': 'Invitee',
                'last_name': 'User',
                'username': 'inviteeuser',
                'password1': '',
                'password2': '',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Account Created!')

        user = User.objects.get(username='inviteeuser')
        invitation.refresh_from_db()
        self.assertFalse(user.has_usable_password())
        self.assertEqual(invitation.status, 'accepted')

    def test_invite_signup_shows_clear_warning_for_mismatched_oauth_email(self):
        organization = Organization.objects.create(org_name='Invite Org')
        sender = User.objects.create_user(
            username='mismatchinviter',
            email='mismatchinviter@example.com',
            password='StrongPassword123!',
            organization=organization,
            is_active=True,
        )
        invitation = Invitation.objects.create(
            sender=sender,
            organization=organization,
            recipient_email='invitee@example.com',
            recipient_role='observer',
            status='sent',
        )

        session = self.client.session
        session['google_signup_verified_email'] = 'wrong@example.com'
        session['social_signup_provider'] = 'Microsoft'
        session['google_invite_prefill'] = {
            'first_name': 'Wrong',
            'last_name': 'Person',
        }
        session.save()

        response = self.client.get(reverse('accounts:accept_invitation', args=[invitation.token]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            'Microsoft signed in as wrong@example.com, but this invitation is for invitee@example.com. Please sign in with the invited email address.',
            html=False,
        )
        self.assertContains(response, "setInvitePasswordRequirement(false);", html=False)
        self.assertNotIn('google_signup_verified_email', self.client.session)

    @override_settings(
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
        DEFAULT_FROM_EMAIL='noreply@example.com',
        ASYNC_EMAIL_ENABLED=False,
    )
    def test_invite_signup_notifies_org_admin_when_account_is_created(self):
        organization = Organization.objects.create(org_name='Invite Notify Org')
        sender = User.objects.create_user(
            username='notifyinviter',
            email='notifyinviter@example.com',
            password='StrongPassword123!',
            organization=organization,
            is_active=True,
        )
        invitation = Invitation.objects.create(
            sender=sender,
            organization=organization,
            recipient_email='teammate@example.com',
            recipient_role='observer',
            status='sent',
        )

        response = self.client.post(
            reverse('accounts:accept_invitation', args=[invitation.token]),
            data={
                'first_name': 'Team',
                'last_name': 'Mate',
                'username': 'teammateuser',
                'password1': 'StrongPassword123!',
                'password2': 'StrongPassword123!',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Account Created!')
        self.assertGreaterEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[-1].subject, 'Team Member Joined Your Organization')
        self.assertIn('notifyinviter@example.com', mail.outbox[-1].to)
        self.assertIn('teammate@example.com', mail.outbox[-1].alternatives[0][0])

    @patch('api.views.id_token.verify_oauth2_token')
    def test_google_oauth_signup_rejects_invite_email_mismatch(self, mock_verify):
        mock_verify.return_value = {
            'email': 'different@example.com',
            'email_verified': True,
        }

        response = self.client.post(
            reverse('google_oauth_signup'),
            data='{"credential": "fake-google-jwt", "purpose": "invite", "expected_email": "invited@example.com"}',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['success'], False)


@override_settings(
    MICROSOFT_OAUTH_CLIENT_ID='test-microsoft-client-id',
    MICROSOFT_OAUTH_CLIENT_SECRET='test-microsoft-client-secret',
    MICROSOFT_OAUTH_TENANT_ID='common',
    MICROSOFT_OAUTH_REQUIRE_OTP=True,
    STORAGES={
        'staticfiles': {
            'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage',
        },
    },
)
class MicrosoftOAuthFlowTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(org_name='Contoso')
        self.user = User.objects.create_user(
            username='msuser',
            email='msuser@example.com',
            password='StrongPassword123!',
            organization=self.org,
            is_active=True,
        )

    def test_microsoft_oauth_start_redirects_to_microsoft_consent_screen(self):
        response = self.client.get(
            reverse('microsoft_oauth_start'),
            {'flow': 'registration', 'next': reverse('accounts:public_register')},
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn('https://login.microsoftonline.com/common/oauth2/v2.0/authorize', response.url)
        self.assertIn('client_id=test-microsoft-client-id', response.url)
        self.assertEqual(self.client.session['microsoft_oauth_flow'], 'registration')

    @override_settings(MICROSOFT_OAUTH_REDIRECT_BASE_URL='http://localhost:8000')
    def test_microsoft_oauth_start_uses_localhost_callback_when_configured(self):
        response = self.client.get(
            reverse('microsoft_oauth_start'),
            {'flow': 'login', 'next': reverse('login')},
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(
            'redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fapi%2Fmicrosoft-oauth%2Fcallback%2F',
            response.url,
        )

    def test_public_register_shows_microsoft_verified_notice_when_microsoft_was_used(self):
        session = self.client.session
        session['verified_email'] = 'msuser@example.com'
        session['google_signup_verified_email'] = 'msuser@example.com'
        session['registration_verified_msuser@example.com'] = True
        session['social_signup_provider'] = 'Microsoft'
        session.save()

        response = self.client.get(reverse('accounts:public_register'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Microsoft already verified this email', html=False)
        self.assertContains(response, 'not required after Microsoft verification', html=False)

    @patch('api.views._exchange_microsoft_code')
    def test_microsoft_oauth_callback_marks_registration_verified(self, mock_exchange):
        mock_exchange.return_value = {
            'preferred_username': 'mscallback@example.com',
            'given_name': 'Morgan',
            'family_name': 'Callback',
        }

        session = self.client.session
        session['microsoft_oauth_state'] = 'ms-state-123'
        session['microsoft_oauth_flow'] = 'registration'
        session['microsoft_oauth_next'] = reverse('accounts:public_register')
        session.save()

        response = self.client.get(
            reverse('microsoft_oauth_callback'),
            {'code': 'sample-code', 'state': 'ms-state-123'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('accounts:public_register'))
        self.assertEqual(self.client.session['verified_email'], 'mscallback@example.com')
        self.assertTrue(self.client.session['registration_verified_mscallback@example.com'])

    @patch('api.views._exchange_microsoft_code')
    def test_microsoft_oauth_callback_shows_expected_invite_email_on_mismatch(self, mock_exchange):
        mock_exchange.return_value = {
            'preferred_username': 'wrong@example.com',
            'given_name': 'Wrong',
            'family_name': 'Microsoft',
        }

        session = self.client.session
        session['microsoft_oauth_state'] = 'ms-invite-state'
        session['microsoft_oauth_flow'] = 'invite'
        session['microsoft_oauth_next'] = reverse('accounts:public_register')
        session['microsoft_oauth_expected_email'] = 'invitee@example.com'
        session.save()

        response = self.client.get(
            reverse('microsoft_oauth_callback'),
            {'code': 'invite-code', 'state': 'ms-invite-state'},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            'Please use the Microsoft account that matches the invited email address: invitee@example.com.',
            html=False,
        )

    @patch('api.views._exchange_microsoft_code')
    def test_microsoft_oauth_callback_starts_otp_for_existing_active_user(self, mock_exchange):
        mock_exchange.return_value = {
            'email': self.user.email,
            'preferred_username': self.user.email,
            'given_name': 'Microsoft',
            'family_name': 'User',
        }

        session = self.client.session
        session['microsoft_oauth_state'] = 'ms-login-state'
        session['microsoft_oauth_flow'] = 'login'
        session['microsoft_oauth_next'] = reverse('login')
        session.save()

        response = self.client.get(
            reverse('microsoft_oauth_callback'),
            {'code': 'login-code', 'state': 'ms-login-state'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('login'))
        self.assertEqual(self.client.session['pending_user_id'], self.user.id)
        self.assertTrue(self.client.session['google_login_requires_otp'])
        self.assertIn('login_otp', self.client.session)

    def test_login_template_shows_microsoft_button_when_client_id_present(self):
        response = self.client.get(reverse('login'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="microsoftSignInButton"', html=False)
        self.assertNotContains(response, 'Set MICROSOFT_OAUTH_CLIENT_ID to enable Microsoft sign-in')