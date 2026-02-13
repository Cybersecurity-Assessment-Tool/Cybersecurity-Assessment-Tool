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
            username = f"{first_name.lower()}_{last_name.lower()}_{i}{org.organization_id.hex[:4]}"

            user = User.objects.create(
                organization=org,
                username=username[:150],
                first_name=first_name,
                last_name=last_name,
                email=f"{first_name.lower()}.{last_name.lower()}@{org.email_domain}",
                is_staff=fake.boolean(chance_of_getting_true=10),
                is_superuser=fake.boolean(chance_of_getting_true=5),
                auto_frequency=random.choice(Frequency.values),
                font_size=random.choice(FontSize.values),
                color=random.choice(Color.values),
                # profile_img is an ImageField and can't be set to a fake value easily, will be empty.
            )
            user.set_password('password123') # set a default password for easy testing
            user.save()

            # assign random permissions
            num_permissions = random.randint(0, 5)
            selected_permissions = random.sample(all_permissions, num_permissions)
            user.user_permissions.set(selected_permissions)

            users.append(user)
    print("Users created successfully.")
    return users

def create_reports(organizations, users, num_reports_per_org=3):
    """Creates fake Report objects."""
    reports = []
    print(f"Creating {num_reports_per_org * len(organizations)} reports...")

    for org in organizations:
        # filter users belonging to the current organization
        org_users = [u for u in users if u.organization == org]
        if not org_users:
            continue

        for _ in range(num_reports_per_org):
            user = random.choice(org_users)
            started_date = fake.date_time_between(start_date="-2y", end_date="now")
            completed_delta = timedelta(minutes=random.randint(30, 180)) 
            report_text_content = fake.paragraph(nb_sentences=10) 

            report = Report.objects.create(
                user_created=user,
                organization=org,
                report_name=fake.catch_phrase() + " Cybersecurity Report",
                # 'started' will be set automatically on creation
                completed=(datetime.now() - completed_delta) if fake.boolean() else None,
                report_text=report_text_content,
                is_checked=fake.boolean(chance_of_getting_true=50)
            )
            reports.append(report)
    print("Reports created successfully.")
    return reports

def create_risks(reports, num_risks_per_report=4):
    """Creates fake Risk objects linked to reports."""
    print(f"Creating risks for {len(reports)} reports...")

    for report in reports:
        for _ in range(random.randint(1, num_risks_per_report)):
            Risk.objects.create(
                risk_name=fake.word().capitalize() + " Risk",
                report=report,
                organization=report.organization,
                overview=fake.paragraph(nb_sentences=5),
                recommendations=[
                    f"Recommendation 1: {fake.sentence()}",
                    f"Recommendation 2: {fake.sentence()}"
                ],
                severity=random.randint(1, 10),
                affected=fake.text(max_nb_chars=100),
                is_archived=fake.boolean(chance_of_getting_true=10),
            )
    print("Risks created successfully.")

class Command(BaseCommand):
    help = 'Populates the database with fake data for development.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE('Starting fake data population...'))

        # 1. Clear existing data to re-populate cleanly
        self.stdout.write(self.style.NOTICE('Clearing existing data...'))
        Risk.objects.all().delete()
        Report.objects.all().delete()
        User.objects.all().delete()
        Organization.objects.all().delete()
        self.stdout.write(self.style.NOTICE('Data cleared.'))

        # 1. Create Organizations
        organizations = create_organizations(num_orgs=5)

        # 2. Create Users
        users = create_users(organizations, num_users_per_org=5)

        # 3. Create Reports
        reports = create_reports(organizations, users, num_reports_per_org=3)

        # 4. Create Risks
        create_risks(reports, num_risks_per_report=4)

        # Superuser for easy login
        if not User.objects.filter(username='superuser').exists():
            User.objects.create_superuser(
                username='superuser',
                email='admin@example.com',
                password='password123',
                organization=organizations[0] # Link to the first organization
            )
            self.stdout.write(self.style.SUCCESS('Created superuser: superuser/password123'))


        self.stdout.write(self.style.SUCCESS('\nFake data population complete!'))