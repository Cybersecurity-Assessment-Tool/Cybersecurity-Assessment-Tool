from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
# Make sure your imports match your actual file structure
from api.models import User, Organization, Color, Frequency, FontSize

# ==========================================
# ⚙️ USER CONFIGURATION
# ==========================================
USER_CONFIG = {
    "username": "test1",
    "password": "password1",
    "email": "test@example.com",
    "first_name": "Test",
    "last_name": "User",
    "is_staff": True,
    "is_superuser": False,
    "is_active": True,
    "color": Color.DARK,
    "font_size": FontSize.MEDIUM,
    "auto_frequency": Frequency.MONTH,
    "assign_to_organization": True, 
    "custom_permissions": [
        "can_invite",
        "can_edit_permissions",
        "can_generate_report",
        "can_export_report",
        "can_resolve_risk",
        "can_generate_risk",
        "view_report",
        "view_risk"
    ]
}

class Command(BaseCommand):
    help = 'Creates a test user with pre-configured settings'

    def handle(self, *args, **options):
        self.stdout.write(f"--- Starting test user creation for '{USER_CONFIG['username']}' ---")

        # 1. Handle Organization
        org = None
        if USER_CONFIG.get("assign_to_organization"):
            org = Organization.objects.first()
            if not org:
                self.stdout.write("No Organization found. Creating a dummy organization...")
                org = Organization.objects.create(
                    org_name="Test Organization",
                    email_domain="test.com",
                    website_domain="test.com",
                    external_ip="192.168.1.1"
                )
            self.stdout.write(f"Linking to Organization: {org.org_name}")

        # 2. Check if user already exists
        if User.objects.filter(username=USER_CONFIG["username"]).exists():
            self.stdout.write(self.style.WARNING(f"[!] User '{USER_CONFIG['username']}' already exists. Skipping creation."))
            return

        # 3. Create the User object
        user = User.objects.create_user(
            username=USER_CONFIG["username"],
            password=USER_CONFIG["password"],
            email=USER_CONFIG["email"],
            first_name=USER_CONFIG["first_name"],
            last_name=USER_CONFIG["last_name"],
            is_staff=USER_CONFIG["is_staff"],
            is_superuser=USER_CONFIG["is_superuser"],
            is_active=USER_CONFIG["is_active"],
            color=USER_CONFIG["color"],
            font_size=USER_CONFIG["font_size"],
            auto_frequency=USER_CONFIG["auto_frequency"],
            organization=org
        )

        # 4. Assign Custom Permissions
        codenames = USER_CONFIG.get("custom_permissions", [])
        if codenames:
            permissions = Permission.objects.filter(codename__in=codenames)
            user.user_permissions.set(permissions)
            
            assigned_perms = [p.codename for p in permissions]
            self.stdout.write(f"Assigned custom permissions: {assigned_perms}")
            
            missing_perms = set(codenames) - set(assigned_perms)
            if missing_perms:
                self.stdout.write(self.style.ERROR(f"[WARNING] Could not find these permissions in the DB: {missing_perms}"))

        self.stdout.write(self.style.SUCCESS(f"✅ Successfully created test user: {user.username} (ID: {user.pk})"))