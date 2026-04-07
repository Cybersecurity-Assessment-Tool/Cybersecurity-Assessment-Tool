"""
This script MUST be run first before running any other code.
It only needs to be run once to configure the tables in the cloud database.
1. python manage.py migrate


For local databases, this should be run whenever the migration has been changed.
Run these commands in your terminal:
1. python manage.py makemigrations
2. python manage.py migrate

How to decrypt the encrypted values:
- Via Django Shell:
    1. python manage.py shell
    2. Then run the following commands:
        from api.model import Organization
        org = Organization.objects.first()
        print(f"Decrypted IP: {org.external_ip}")
- Via PostgreSQL:
    Locally:
        ex: SELECT external_ip FROM api_organization
    On Heroku:
        ex: heroku pg:psql -a your-app-name
            SELECT external_ip FROM api_organization LIMIT 1;
"""
import os
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from encrypted_fields.fields import EncryptedCharField, EncryptedTextField, EncryptedJSONField, EncryptedEmailField
from datetime import timedelta
from django.utils import timezone
import hashlib
from django.conf import settings

def get_otp_expiration():
    return timezone.now() + timedelta(minutes=5)

def generate_email_hash(email: str) -> str:
    """
    Generates a secure, deterministic hash for an email address.
    Used for enforcing uniqueness on encrypted email fields.
    """
    if not email:
        return None
        
    # 1. Normalize the email (lowercase and strip whitespace)
    normalized_email = email.strip().lower()
    
    # 2. Add a salt (using Django's SECRET_KEY) to prevent rainbow table attacks
    salted_email = f"{normalized_email}{settings.SECRET_KEY}"
    
    # 3. Generate and return the SHA-256 hex digest (64 characters)
    return hashlib.sha256(salted_email.encode('utf-8')).hexdigest()

class Color(models.TextChoices):
    DARK = 'd', 'Dark'
    LIGHT = 'l', 'Light'

class Frequency(models.TextChoices):
    NONE = 'n', 'None'
    MONTH = 'm', 'Monthly'
    QUARTER = 'q', 'Quarterly'
    YEAR = 'y', 'Yearly'

class FontSize(models.TextChoices):
    LARGE = 'l', 'Large'
    MEDIUM = 'm', 'Medium'
    SMALL = 's', 'Small'

class Organization(models.Model):
    organization_id = models.UUIDField(
        primary_key = True,
        default=uuid.uuid4,
        editable=False
    )
    org_name = EncryptedCharField(max_length=300)
    email_domain = EncryptedCharField(max_length=100, null=True, blank=True)
    website_domain = EncryptedCharField(max_length=100, null=True, blank=True)
    external_ip = EncryptedCharField(max_length=100, null=True, blank=True)
    
    # Questionnaire questions
    # TODO: edit these to the question bank
    require_mfa_email = models.BooleanField(null=True, blank=True, default=False)
    require_mfa_computer = models.BooleanField(null=True, blank=True, default=False)
    require_mfa_sensitive_data = models.BooleanField(null=True, blank=True, default=False)
    employee_acceptable_use_policy = models.BooleanField(null=True, blank=True, default=False)
    training_new_employees = models.BooleanField(null=True, blank=True, default=False)
    training_once_per_year = models.BooleanField(null=True, blank=True,default=False)
    registration_status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending Approval'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
        ],
        default='pending'
    )
    questionnaire_completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.org_name

# AbstractUser already provides username, password, and email
class User(AbstractUser):
    def profile_image_path(instance, filename):
        """Generate file path for a user's profile image."""
        ext = filename.split('.')[-1]
        identifier = instance.user_id or instance.pk or 'new'
        filename = f"profile_{instance.username}_{identifier}.{ext}"
        return os.path.join('uploads/profile_images/', filename)

    user_id = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False
    )
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='api_user_groups',
        blank=True,
        help_text='The groups this user belongs to (e.g., Executive, Manager, Technician, etc.)',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='api_user_permissions',
        blank=True,
        help_text='Specific permissions for this user (for exceptions).',
        verbose_name='user permissions',
    )
    organization = models.ForeignKey(
        Organization, 
        on_delete=models.CASCADE,
        null=True,     # allows null value in the database
        blank=True     # allows the field to be optional in forms/admin
    )
    auto_frequency = models.CharField(max_length=1, choices=Frequency.choices)
    profile_image = models.ImageField(upload_to=profile_image_path, blank=True, null=True, db_column='profile_img')
    color = models.CharField(max_length=1, choices=Color.choices, default=Color.DARK)
    font_size = models.CharField(max_length=1, choices=FontSize.choices, default=FontSize.MEDIUM)
    email_inbox = EncryptedEmailField(null=True, blank=True)
    email = EncryptedEmailField()
    email_hash = models.CharField(max_length=64, unique=True, null=True, blank=True)
    password = EncryptedCharField(max_length=128)
    first_name = EncryptedCharField(max_length=50, null=True, blank=True)
    last_name = EncryptedCharField(max_length=50, null=True, blank=True)
        
    def save(self, *args, **kwargs):
        # Automatically generate the hash whenever the user is saved/updated
        if self.email:
            self.email_hash = generate_email_hash(self.email)
        super().save(*args, **kwargs)

    class Meta:
        permissions = [
            ("can_invite", "Can invite users to the organization."),
            ("can_edit_permissions", "Can edit users' permissions in the organization."),
        ]
    
    def __str__(self):
        return self.username
    
    def get_username(self):
        """Return username"""
        return self.username

class Report(models.Model):
    report_id = models.UUIDField(
        primary_key = True,
        default=uuid.uuid4,
        editable=False
    )
    user_created = models.ForeignKey(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    report_name = models.CharField(max_length=300)
    started = models.DateTimeField(auto_now_add=True)
    completed = models.DateTimeField(blank=True, null=True)
    report_text = EncryptedJSONField(default=dict)
    #is_checked = models.BooleanField(default=False)

    class Meta:
        permissions = [
            #("can_check_report", "Can check a report before publishing."),
            ("can_view_any_report", "Can review any report, regardless of organization."),
            ("can_generate_report", "Can generate a new report."),
            ("can_export_report", "Can export report data."),
        ]

    def __str__(self):
        return self.report_name

class Risk(models.Model):
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Info', 'Informational')
    ]
    risk_id = models.UUIDField(
        primary_key = True,
        default=uuid.uuid4,
        editable=False
    )
    risk_name = models.CharField(max_length=500)
    # The report that the risk was created from
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    # The organization that the risk is tied to
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    overview = EncryptedTextField()
    recommendations = EncryptedJSONField()
    severity = models.CharField(choices=SEVERITY_CHOICES)
    affected_elements = EncryptedTextField()
    is_archived = models.BooleanField(default=False)

    class Meta:
        permissions = [
            ("can_view_risk", "Can view the risk."),
            ("can_view_all_risk", "Can view any risk, regardless of organization."),
            ("can_resolve_risk", "Can resolve the risk and set as archived."),
            ("can_generate_risk", "Can generate new risks."),
        ]

    def __str__(self):
        return f"{self.severity}: {self.risk_name}"


class Invitation(models.Model):
    STATUS_CHOICES = (
        ('sent', 'Sent'),
        ('awaiting_approval', 'Awaiting Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    )
    
    RECIPIENT_ROLE_CHOICES = (
        ('org_admin', 'Org Admin'),
        ('observer', 'Observer'),
        ('tester', 'Tester'),
    )

    def is_valid(self):
        """Check if invitation is still valid (not expired)"""
        from django.utils import timezone
        from datetime import timedelta
        return self.status == 'sent' and self.created_at >= timezone.now() - timedelta(days=7)
    
    invitation_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    # The user who sent the invite
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sent_invitations'
    )
    # The organization the new user is being invited to join
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='invitations'
    )
    # The email address the invite was sent to
    recipient_email = EncryptedEmailField()
    recipient_email_hash = models.CharField(max_length=64, unique=True, null=True, blank=True)
    
    # The new user account (null until they click the link and sign up)
    recipient_user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='received_invitations'
    )
    # A secure, unique token for the email link
    token = models.UUIDField(
        default=uuid.uuid4, 
        editable=False, 
        unique=True
    )
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='sent'
    )
    recipient_role = models.CharField(
        max_length=20,
        choices=RECIPIENT_ROLE_CHOICES,
        default='observer',
    )# Default role for new users, can be changed by admin later
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        # Automatically generate the hash whenever the invitation is saved
        if self.recipient_email:
            self.recipient_email_hash = generate_email_hash(self.recipient_email)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Invite from {self.sender.username} to {self.recipient_email} - {self.status}"

    
class OTPVerification(models.Model):
    """Store OTP codes for email verification"""
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=20, choices=[
        ('registration', 'Registration'),
        ('login', 'Login'),
        ('invitation', 'Invitation'),
    ])
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=get_otp_expiration)
    is_verified = models.BooleanField(default=False)
    
    class Meta:
        indexes = [
            models.Index(fields=['email', 'otp_code', 'purpose']),
        ]
    
    def is_valid(self):
        return not self.is_verified and self.expires_at > timezone.now()


import json
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _get_fernet():
    """Returns a Fernet instance using the project encryption key."""
    key = settings.FIELD_ENCRYPTION_KEY
    if not key:
        raise ValueError("FIELD_ENCRYPTION_KEY is not set in settings.")
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_value(value: str) -> str:
    """Encrypt a string value. Returns a UTF-8 encoded ciphertext string."""
    if not value:
        return value
    f = _get_fernet()
    return f.encrypt(value.encode()).decode()


def decrypt_value(token: str) -> str:
    """Decrypt a ciphertext string. Returns plaintext or raises InvalidToken."""
    if not token:
        return token
    f = _get_fernet()
    return f.decrypt(token.encode()).decode()


# ---------------------------------------------------------------------------
# Encrypted field descriptor
# ---------------------------------------------------------------------------

class FernetEncryptedTextField(models.TextField):
    """
    A TextField that transparently encrypts on save and decrypts on load.
    Sensitive fields (raw JSON results, subnet, findings) use this field type.
    """
    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        return name, path, args, kwargs

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        try:
            return decrypt_value(value)
        except (InvalidToken, Exception):
            # If decryption fails (e.g. dev data without encryption), return raw
            return value

    def get_prep_value(self, value):
        if value is None:
            return value
        # Avoid double-encrypting already encrypted values
        try:
            decrypt_value(value)
            return value  # already encrypted
        except Exception:
            return encrypt_value(value)


# ---------------------------------------------------------------------------
# ScanToken model
# ---------------------------------------------------------------------------

class ScanToken(models.Model):
    """
    One-time signed token generated when the user requests a scanner download.
    Tied to a specific user and organization. Expires after 24 hours.
    Consumed (marked used) when the exe POSTs results back.
    """

    token = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='scan_tokens',
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='scan_tokens',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Scan Token'
        verbose_name_plural = 'Scan Tokens'

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)

    @property
    def is_valid(self):
        """Returns True if the token is unused and not expired."""
        return not self.is_used and timezone.now() < self.expires_at

    def consume(self):
        """Mark the token as used."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])

    def __str__(self):
        return f"ScanToken({self.token}) - {'used' if self.is_used else 'valid'})"


# ---------------------------------------------------------------------------
# Scan model
# ---------------------------------------------------------------------------

class Scan(models.Model):
    """
    Represents a single network scan initiated by a user.

    Lifecycle:
        PENDING   → Token generated, exe downloaded, scan not yet started
        RUNNING   → Exe is actively scanning (future: real-time updates)
        RECEIVED  → JSON results POSTed by exe, Gemini report task queued
        GENERATING → Django-Q2 task running Gemini report generation
        COMPLETE  → Report generated and stored
        FAILED    → Any stage failed
    """

    class Status(models.TextChoices):
        PENDING    = 'PENDING',    'Pending'
        RUNNING    = 'RUNNING',    'Running'
        RECEIVED   = 'RECEIVED',   'Results Received'
        GENERATING = 'GENERATING', 'Generating Report'
        COMPLETE   = 'COMPLETE',   'Complete'
        FAILED     = 'FAILED',     'Failed'

    class Severity(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Critical'
        HIGH     = 'HIGH',     'High'
        MEDIUM   = 'MEDIUM',   'Medium'
        LOW      = 'LOW',      'Low'
        INFO     = 'INFO',     'Info'

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='scans',
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='scans',
    )
    token = models.OneToOneField(
        ScanToken,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scan',
    )

    # ------------------------------------------------------------------
    # Status tracking
    # ------------------------------------------------------------------
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    error_message = models.TextField(blank=True, null=True)

    # Django-Q2 task ID for the Gemini report generation task
    report_task_id = models.CharField(max_length=255, blank=True, null=True)

    # ------------------------------------------------------------------
    # Timing
    # ------------------------------------------------------------------
    created_at = models.DateTimeField(auto_now_add=True)
    scan_started_at = models.DateTimeField(null=True, blank=True)
    scan_completed_at = models.DateTimeField(null=True, blank=True)
    report_completed_at = models.DateTimeField(null=True, blank=True)

    # Reported by the exe itself
    scan_duration_seconds = models.PositiveIntegerField(null=True, blank=True)

    # ------------------------------------------------------------------
    # Scan metadata (encrypted - reveals network topology)
    # ------------------------------------------------------------------
    target_subnet = EncryptedTextField(
        blank=True,
        null=True,
        help_text="Encrypted. The subnet that was scanned (e.g. 192.168.1.0/24)."
    )
    scanner_version = models.CharField(max_length=20, blank=True, null=True)
    groups_completed = models.PositiveSmallIntegerField(default=0)
    skipped_tools = models.JSONField(default=list, blank=True)

    # ------------------------------------------------------------------
    # Results (encrypted - raw vulnerability data)
    # ------------------------------------------------------------------
    raw_findings_json = EncryptedJSONField(
        blank=True,
        null=True,
        help_text="Encrypted. Full JSON findings from the exe. Deleted after report generation."
    )

    # Summary stats derived from findings (not encrypted - aggregate only)
    finding_count_critical = models.PositiveSmallIntegerField(default=0)
    finding_count_high      = models.PositiveSmallIntegerField(default=0)
    finding_count_medium    = models.PositiveSmallIntegerField(default=0)
    finding_count_low       = models.PositiveSmallIntegerField(default=0)
    finding_count_info      = models.PositiveSmallIntegerField(default=0)

    # ------------------------------------------------------------------
    # Report (FK to your existing Report model once generated)
    # ------------------------------------------------------------------
    report = models.OneToOneField(
        Report,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scan',
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Scan'
        verbose_name_plural = 'Scans'

    def __str__(self):
        return f"Scan({self.id}) - {self.user} - {self.status}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_findings(self) -> list:
        """Deserialize and return findings list from encrypted JSON."""
        if not self.raw_findings_json:
            return []
        try:
            return json.loads(self.raw_findings_json)
        except json.JSONDecodeError:
            return []

    def set_findings(self, findings: list):
        """Serialize and store findings list to encrypted JSON field."""
        self.raw_findings_json = json.dumps(findings)

    def tally_findings(self, findings: list):
        """Populate severity count fields from a findings list."""
        counts = {s: 0 for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']}
        for f in findings:
            severity = f.get('severity', 'INFO').upper()
            if severity in counts:
                counts[severity] += 1
        self.finding_count_critical = counts['CRITICAL']
        self.finding_count_high     = counts['HIGH']
        self.finding_count_medium   = counts['MEDIUM']
        self.finding_count_low      = counts['LOW']
        self.finding_count_info     = counts['INFO']

    def purge_raw_findings(self):
        """
        Delete raw JSON findings after report generation.
        The report holds the AI-processed summary; raw data is no longer needed.
        """
        self.raw_findings_json = None
        self.save(update_fields=['raw_findings_json'])

    @property
    def total_findings(self):
        return (
            self.finding_count_critical +
            self.finding_count_high +
            self.finding_count_medium +
            self.finding_count_low +
            self.finding_count_info
        )

    @property
    def is_complete(self):
        return self.status == self.Status.COMPLETE

    @property
    def has_failed(self):
        return self.status == self.Status.FAILED
    

# ---------------------------------------------------------------------------
# Way of deleting invitations when a user is deleted
# ---------------------------------------------------------------------------

from django.db.models.signals import post_delete
from django.dispatch import receiver

@receiver(post_delete, sender=User)
def delete_associated_invitation(sender, instance, **kwargs):
    """Delete invitation linked to a user when the user is deleted."""
    Invitation.objects.filter(recipient_user=instance).delete()