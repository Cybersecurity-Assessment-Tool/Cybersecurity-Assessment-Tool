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
            {'name': 'Remote Code Execution in Apache', 'severity': 'Critical', 'description': 'Apache HTTP Server 2.4.48 and earlier allows remote code execution'},
            {'name': 'SQL Injection Vulnerability', 'severity': 'Critical', 'description': 'Blind SQL injection in login parameter'},
            {'name': 'Default Admin Credentials', 'severity': 'Critical', 'description': 'Default username/password combination still enabled'},
            
            # High severity
            {'name': 'Outdated SSL/TLS Configuration', 'severity': 'High', 'description': 'Server supports weak SSL/TLS protocols'},
            {'name': 'Cross-Site Scripting (XSS)', 'severity': 'High', 'description': 'Reflected XSS in search parameter'},
            {'name': 'Weak Password Policy', 'severity': 'High', 'description': 'Password policy allows weak passwords'},
            
            # Medium severity
            {'name': 'Missing HTTP Security Headers', 'severity': 'Medium', 'description': 'X-Frame-Options, CSP headers missing'},
            {'name': 'Directory Listing Enabled', 'severity': 'Medium', 'description': 'Web server exposes directory contents'},
            {'name': 'Session Fixation', 'severity': 'Medium', 'description': 'Session ID not regenerated after login'},
            
            # Low severity
            {'name': 'Server Banner Disclosure', 'severity': 'Low', 'description': 'Server reveals version information'},
            {'name': 'Cookie Without Secure Flag', 'severity': 'Low', 'description': 'Cookies transmitted over unencrypted connection'},
            {'name': 'Unnecessary Service Running', 'severity': 'Low', 'description': 'Unused network service is enabled'},
        ]
        
        # Create vulnerabilities
        for vuln_data in dummy_vulnerabilities:
            Vulnerability.objects.create(**vuln_data)
            self.stdout.write(f'Created: {vuln_data["name"]}')
        
        self.stdout.write(self.style.SUCCESS(f'Successfully added {len(dummy_vulnerabilities)} vulnerabilities'))