from django.core.management.base import BaseCommand
from api.models import Vulnerability  # Adjust 'api' to your actual app name

class Command(BaseCommand):
    help = 'Adds dummy vulnerability data to the database'

    def handle(self, *args, **kwargs):
        # Clear existing data (optional)
        Vulnerability.objects.all().delete()
        
        # Dummy vulnerability data (AI SLOP)
        dummy_vulnerabilities = [
            # Critical severity
            {'risk_name': 'Remote Code Execution in Apache', 'severity': 'Critical', 'overview': 'Apache HTTP Server 2.4.48 and earlier allows remote code execution'},
            {'risk_name': 'SQL Injection Vulnerability', 'severity': 'Critical', 'overview': 'Blind SQL injection in login parameter'},
            {'risk_name': 'Default Admin Credentials', 'severity': 'Critical', 'overview': 'Default username/password combination still enabled'},
            
            # High severity
            {'risk_name': 'Outdated SSL/TLS Configuration', 'severity': 'High', 'overview': 'Server supports weak SSL/TLS protocols'},
            {'risk_name': 'Cross-Site Scripting (XSS)', 'severity': 'High', 'overview': 'Reflected XSS in search parameter'},
            {'risk_name': 'Weak Password Policy', 'severity': 'High', 'overview': 'Password policy allows weak passwords'},
            
            # Medium severity
            {'risk_name': 'Missing HTTP Security Headers', 'severity': 'Medium', 'overview': 'X-Frame-Options, CSP headers missing'},
            {'risk_name': 'Directory Listing Enabled', 'severity': 'Medium', 'overview': 'Web server exposes directory contents'},
            {'risk_name': 'Session Fixation', 'severity': 'Medium', 'overview': 'Session ID not regenerated after login'},
            
            # Low severity
            {'risk_name': 'Server Banner Disclosure', 'severity': 'Low', 'overview': 'Server reveals version information'},
            {'risk_name': 'Cookie Without Secure Flag', 'severity': 'Low', 'overview': 'Cookies transmitted over unencrypted connection'},
            {'risk_name': 'Unnecessary Service Running', 'severity': 'Low', 'overview': 'Unused network service is enabled'},
        ]
        
        # Create vulnerabilities
        for vuln_data in dummy_vulnerabilities:
            Vulnerability.objects.create(**vuln_data)
            self.stdout.write(f'Created: {vuln_data["name"]}')
        
        self.stdout.write(self.style.SUCCESS(f'Successfully added {len(dummy_vulnerabilities)} vulnerabilities'))