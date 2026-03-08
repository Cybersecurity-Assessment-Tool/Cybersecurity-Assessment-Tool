from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from api.models import User, Organization, Color, Frequency, FontSize

# ==========================================
# ⚙️ USER CONFIGURATION
# Edit these values before running the script
# ==========================================
USER_CONFIG = {
    "username": "test",
    "password": "password",
    "email": "test@example.com",
    "first_name": "Test",
    "last_name": "User",
    
    # Standard Django User fields
    "is_staff": True,
    "is_superuser": False,
    "is_active": True,
    
    # Custom User fields
    "color": Color.DARK,
    "font_size": FontSize.MEDIUM,
    "auto_frequency": Frequency.MONTH,
    
    # Organization Setup
    # If True, links user to the first existing Organization (or creates a dummy one)
    "assign_to_organization": True, 
    
    # Permissions
    # Add the codenames of the custom permissions you want to assign
    "custom_permissions": [
        "can_invite",
        "can_edit_permissions",
        # "can_view_any_report",
        "can_generate_report",
        "can_export_report",
        # "can_view_all_risk",
        "can_resolve_risk",
        "can_generate_risk",
        "view_report",
        "view_risk"
    ]
}

def run():
    print(f"--- Starting test user creation for '{USER_CONFIG['username']}' ---")

    # 1. Handle Organization
    org = None
    if USER_CONFIG.get("assign_to_organization"):
        org = Organization.objects.first()
        if not org:
            print("No Organization found. Creating a dummy organization...")
            org = Organization.objects.create(
                org_name="Test Organization",
                email_domain="test.com",
                website_domain="test.com",
                external_ip="192.168.1.1"
            )
        print(f"Linking to Organization: {org.org_name}")

    # 2. Check if user already exists to prevent duplication errors
    if User.objects.filter(username=USER_CONFIG["username"]).exists():
        print(f"[!] User '{USER_CONFIG['username']}' already exists. Skipping creation.")
        return

    # 3. Create the User object
    # We use create_user so the password is automatically hashed
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
        print(f"Assigned custom permissions: {assigned_perms}")
        
        missing_perms = set(codenames) - set(assigned_perms)
        if missing_perms:
            print(f"[WARNING] Could not find these permissions in the DB: {missing_perms}")

    print(f"✅ Successfully created test user: {user.username} (ID: {user.user_id})")