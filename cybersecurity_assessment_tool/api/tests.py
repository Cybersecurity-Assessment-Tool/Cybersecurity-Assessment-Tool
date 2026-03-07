from unittest.mock import patch
from django.test import TestCase
from django.utils import timezone
from api.models import Organization, User, Report, Risk
from api.services.gemini_client import (
    get_severity_weight,
    build_current_risks_dict,
    _inject_overview_and_questionnaire,
    generate_and_process_report
)

# Gemini Client Tests
class GeminiClientTests(TestCase):
    def setUp(self):
        # Set up prerequisite models
        self.org = Organization.objects.create(
            org_name="Wayne Enterprises",
            email_domain="wayne.com",
            website_domain="wayne.com",
            external_ip="198.51.100.14",
            require_mfa_email=True,
            require_mfa_computer=False
        )
        
        self.user = User.objects.create_user(
            username="bwayne",
            password="securepassword123",
            organization=self.org
        )

    def test_get_severity_weight(self):
        """Test that severities map to the correct sorting integers."""
        self.assertEqual(get_severity_weight("Critical"), 1)
        self.assertEqual(get_severity_weight("High"), 2)
        self.assertEqual(get_severity_weight("Info"), 5)
        # Test case insensitivity and unknown values
        self.assertEqual(get_severity_weight("critical"), 1) 
        self.assertEqual(get_severity_weight("UnknownSeverity"), 6)

    def test_build_current_risks_dict(self):
        """Test that existing DB risks are correctly formatted for the AI prompt."""
        # Create a mock existing risk
        report = Report.objects.create(report_name="Old Report", user_created=self.user, organization=self.org)
        Risk.objects.create(
            risk_name="Old SQLi",
            report=report,
            organization=self.org,
            overview="Old issue",
            severity="High",
            affected_elements="DB1, DB2",
            recommendations={
                "easy_fix": "Apply immediate database patch.",
                "long_term_fix": "Implement parameterized queries across the application."
            }
        )

        risks_dict = build_current_risks_dict(self.org.organization_id)
        
        # Assert the dictionary structure matches what the AI expects
        self.assertIn("all_vulnerabilities", risks_dict)
        self.assertEqual(len(risks_dict["all_vulnerabilities"]), 1)
        self.assertEqual(risks_dict["all_vulnerabilities"][0]["risk_name"], "Old SQLi")
        self.assertEqual(risks_dict["all_vulnerabilities"][0]["affected_elements"], ["DB1", "DB2"])

    def test_inject_overview_and_questionnaire(self):
        """Test that the DB context is successfully injected into the raw AI report data."""
        raw_ai_report = {
            "report": [{
                "Risks & Recommendations": {},
                "Conclusion": "Test conclusion"
            }]
        }

        injected_report = _inject_overview_and_questionnaire(raw_ai_report, self.org)
        
        # Check that the Overview and Questionnaire Review were prepended
        first_item = injected_report["report"][0]
        self.assertIn("Overview", first_item)
        self.assertIn("Questionnaire Review", first_item)
        self.assertEqual(first_item["Overview"]["Organization Name"], "Wayne Enterprises")
        self.assertEqual(first_item["Questionnaire Review"]["Do you require MFA to access email?"], "Yes")
        self.assertEqual(first_item["Questionnaire Review"]["Do you require MFA to log into computers?"], "No")

    @patch('api.services.gemini_client.ai_generation_service')
    def test_generate_and_process_report_success(self, mock_ai_service):
        """Test the full pipeline with a mocked successful AI response."""
        
        # 1. Define the fake data the AI *would* have returned
        mock_report_data = {
            "report": [{
                "Risks & Recommendations": {
                    "Vulnerabilities Found": [
                        {"Risk": "Low Risk Issue", "Severity": "Low"},
                        {"Risk": "Critical Risk Issue", "Severity": "Critical"}
                    ]
                }
            }]
        }
        
        mock_risks_data = {
            "new vulnerabilities": [
                {
                    "risk_name": "Critical Risk Issue",
                    "overview": "A bad vulnerability.",
                    "severity": "Critical",
                    "affected_elements": ["Server A"],
                    "recommendations": {"easy_fix": "Patch it"}
                }
            ]
        }
        
        # Configure the mock to return our fake data tuple
        mock_ai_service.return_value = (mock_report_data, mock_risks_data)

        # 2. Call the client function
        report, risks = generate_and_process_report(
            organization_id=self.org.organization_id,
            user_id=self.user.user_id,
            context_data="Fake port scan data"
        )

        # 3. Assertions
        # Check that the mock was actually called
        mock_ai_service.assert_called_once()
        
        # Check that the Report and Risks were actually created and returned
        self.assertIsNotNone(report)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0].risk_name, "Critical Risk Issue")
        
        # Check that the JSON vulnerabilities were sorted properly (Critical before Low)
        saved_report_data = report.report_text
        vulns = saved_report_data["report"][0]["Risks & Recommendations"]["Vulnerabilities Found"]
        self.assertEqual(vulns[0]["Severity"], "Critical")
        self.assertEqual(vulns[1]["Severity"], "Low")

    @patch('api.services.gemini_client.ai_generation_service')
    def test_generate_and_process_report_ai_failure(self, mock_ai_service):
        """Test that the system handles an AI pipeline failure gracefully."""
        
        # Simulate the AI service failing and returning None, None
        mock_ai_service.return_value = (None, None)

        report, risks = generate_and_process_report(
            organization_id=self.org.organization_id,
            user_id=self.user.user_id,
            context_data="Fake port scan data"
        )

        # Assert that it handled the failure safely
        self.assertIsNone(report)
        self.assertIsNone(risks)
        self.assertEqual(Report.objects.count(), 0) # Ensure nothing was saved

# Database Encryption Tests
class DatabaseEncryptionTests(TestCase):
    def setUp(self):
        # 1. Set up the prerequisite models
        self.org = Organization.objects.create(
            org_name="Wayne Enterprises",
            email_domain="wayne.com",
            website_domain="wayne.com",
            external_ip="198.51.100.14"
        )
        
        self.user = User.objects.create_user(
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