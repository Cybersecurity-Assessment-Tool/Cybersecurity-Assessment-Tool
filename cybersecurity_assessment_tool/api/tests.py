from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse

from api.models import Organization, User, Report, Risk

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


@override_settings(GOOGLE_OAUTH_CLIENT_ID='test-google-client-id.apps.googleusercontent.com')
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
    def test_google_oauth_logs_in_existing_active_user(self, mock_verify):
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