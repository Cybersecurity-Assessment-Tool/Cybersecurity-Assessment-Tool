import random
import uuid
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from api.models import FontSize, Organization, User, Report, Risk, Color, Frequency
from faker import Faker

fake = Faker()

def create_organizations(num_orgs=5):
    """Creates fake Organization objects."""
    orgs = []
    print(f"Creating {num_orgs} organizations...")
    for _ in range(num_orgs):
        org = Organization.objects.create(
            org_name=fake.company(),
            email_domain=fake.domain_name(),
            website_domain=fake.domain_name(),
            external_ip=fake.ipv4(),
            require_mfa_email=fake.boolean(),
            require_mfa_sensitive_data=fake.boolean(),
            require_mfa_computer=fake.boolean(),
            employee_acceptable_use_policy=fake.boolean(),
            training_new_employees=fake.boolean(),
            training_once_per_year=fake.boolean(),
        )
        orgs.append(org)
    print("Organizations created successfully.")
    return orgs

def create_users(organizations, num_users_per_org=5):
    """Creates fake User objects linked to organizations."""
    users = []
    all_permissions = list(Permission.objects.all())
    print(f"Creating {num_users_per_org * len(organizations)} users...")

    for org in organizations:
        for i in range(num_users_per_org):
            first_name = fake.first_name()
            last_name = fake.last_name()
            # UUID hex used for uniqueness
            username = f"{first_name.lower()}_{last_name.lower()}_{i}_{org.organization_id.hex[:4]}"

            user = User.objects.create(
                organization=org,
                username=username[:150],
                first_name=first_name,
                last_name=last_name,
                email=f"{first_name.lower()}.{last_name.lower()}@{org.email_domain}",
                is_staff=fake.boolean(chance_of_getting_true=10),
                is_superuser=False,
                auto_frequency=random.choice(Frequency.values),
                font_size=random.choice(FontSize.values),
                color=random.choice(Color.values),
            )
            user.set_password('password123')
            user.save()

            # Assign random permissions
            num_permissions = random.randint(0, 5)
            selected_permissions = random.sample(all_permissions, num_permissions)
            user.user_permissions.set(selected_permissions)

            users.append(user)
    print("Users created successfully.")
    return users

def create_reports(organizations, users, num_reports_per_org=3):
    """Creates fake Report objects matching EncryptedJSONField."""
    reports = []
    print(f"Creating {num_reports_per_org * len(organizations)} reports...")

    for org in organizations:
        org_users = [u for u in users if u.organization == org]
        if not org_users:
            continue

        for _ in range(num_reports_per_org):
            user = random.choice(org_users)
            
            # Matching the new report_text EncryptedJSONField
            report_data = {
                "executive_summary": fake.paragraph(),
                "scope": fake.sentence(),
                "methodology": "Automated Scan and Manual Review",
                "findings_count": random.randint(1, 20)
            }

            report = Report.objects.create(
                user_created=user,
                organization=org,
                report_name=fake.catch_phrase() + " Cybersecurity Report",
                completed=datetime.now() if fake.boolean() else None,
                report_text=report_data,  # Now a dict for JSONField
            )
            reports.append(report)
    print("Reports created successfully.")
    return reports

def create_risks(reports, num_risks_per_report=4):
    """Creates fake Risk objects matching new severity choices and field names."""
    print(f"Creating risks for {len(reports)} reports...")

    severity_list = [choice[0] for choice in Risk.SEVERITY_CHOICES]

    for report in reports:
        for _ in range(random.randint(1, num_risks_per_report)):
            # Matching the new recommendations EncryptedJSONField
            recs = {
                "immediate_action": fake.sentence(),
                "long_term_strategy": fake.sentence(),
                "references": [fake.url() for _ in range(2)]
            }

            Risk.objects.create(
                risk_name=fake.word().capitalize() + " Risk",
                report=report,
                organization=report.organization,
                overview=fake.paragraph(nb_sentences=5),
                recommendations=recs,  # Now a dict for JSONField
                severity=random.choice(severity_list), # Choice string instead of int
                affected_elements=fake.text(max_nb_chars=100), # Renamed from 'affected'
                is_archived=fake.boolean(chance_of_getting_true=10),
            )
    print("Risks created successfully.")

class Command(BaseCommand):
    help = 'Populates the database with fake data for development.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE('Starting fake data population...'))

        # 1. Clear existing data
        self.stdout.write(self.style.NOTICE('Clearing existing data...'))
        Risk.objects.all().delete()
        Report.objects.all().delete()
        User.objects.all().delete()
        Organization.objects.all().delete()

        # 2. Re-populate
        organizations = create_organizations(num_orgs=5)
        users = create_users(organizations, num_users_per_org=5)
        reports = create_reports(organizations, users, num_reports_per_org=3)
        create_risks(reports, num_risks_per_report=4)

        # Superuser creation
        if not User.objects.filter(username='superuser').exists():
            User.objects.create_superuser(
                username='superuser',
                email='admin@example.com',
                password='password123',
                organization=organizations[0]
            )
            self.stdout.write(self.style.SUCCESS('Created superuser: superuser/password123'))

        self.stdout.write(self.style.SUCCESS('Fake data population complete!'))