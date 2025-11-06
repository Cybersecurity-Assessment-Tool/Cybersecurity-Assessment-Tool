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
    font_size = models.CharField(max_length=1, choices=FontSize.choices, default=FontSize.MEDIUM)
    color = models.CharField(max_length=1, choices=Color.choices, default=Color.DARK)

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
    date_created = models.DateTimeField(auto_now_add=True)
    started = models.DateTimeField(auto_now_add=True)
    completed = models.DateTimeField(blank=True, null=True)
    report_text = models.JSONField()

    def __str__(self):
        return self.report_name

class Risk(models.Model):
    risk_name = models.CharField(max_length=300)
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    overview_text = models.TextField()
    recommendation_text = models.TextField()
    severity = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(10)])
    affected = models.IntegerField(default=0)
    is_archived = models.BooleanField(default=False)

    def __str__(self):
        return self.risk_name