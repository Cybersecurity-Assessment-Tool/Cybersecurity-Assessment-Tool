"""
This script MUST be run first before running any other code.
It only needs to be run once to configure the tables in the cloud database.
For local databases, it should be run regularly whenever the migration has been changed.

Run these commands in your terminal:
1. python manage.py makemigrations
2. python manage.py migrate
"""
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator

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
    org_name = models.CharField(max_length=300)
    email_domain = models.CharField(max_length=100)
    website_domain = models.CharField(max_length=100)
    external_ip = models.CharField(max_length=100)
    require_mfa_email = models.BooleanField()
    require_mfa_sensitive_data = models.BooleanField()
    employee_acceptable_use_policy = models.BooleanField()
    training_new_employees = models.BooleanField()
    training_once_per_year = models.BooleanField()

    def __str__(self):
        return self.org_name

# AbstractUser already provides username, password, and email
class User(AbstractUser):
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
    organization = organization = models.ForeignKey(
        Organization, 
        on_delete=models.CASCADE,
        null=True,     # allows null value in the database
        blank=True     # allows the field to be optional in forms/admin
    )
    auto_frequency = models.CharField(max_length=1, choices=Frequency.choices)
    profile_img = models.ImageField()
    color = models.CharField(max_length=1, choices=Color.choices, default=Color.DARK)
    font_size = models.CharField(max_length=1, choices=FontSize.choices, default=FontSize.MEDIUM)

    class Meta:
        permissions = [
            ("can_invite", "Can invite users to the organization."),
            ("can_edit_permissions", "Can edit users' permissions in the organization."),
        ]
    
    def __str__(self):
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
    report_text = models.JSONField(default=dict)
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
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    overview = models.TextField()
    recommendations = models.JSONField()
    severity = models.CharField(choices=SEVERITY_CHOICES)
    affected_elements = models.TextField()
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