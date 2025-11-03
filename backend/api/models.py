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

def user_directory_path(instance, filename):
    return f'user_{instance.user.user_id}/img/{filename}'

class Color(models.TextChoices):
    DARK = 'd', 'Dark'
    LIGHT = 'l', 'Light'

class Frequency(models.TextChoices):
    MONTH = 'm', 'Monthly'
    QUARTER = 'q', 'Quarterly'

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
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='api_user_permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    is_automated = models.BooleanField(default=False)
    auto_frequency = models.CharField(max_length=1, choices=Frequency.choices)
    profile_img = models.FileField(upload_to=user_directory_path, blank=True, null=True)
    font_size = models.IntegerField(default=12) #TODO: check and edit default value
    color = models.CharField(max_length=1, choices=Color.choices, default=Color.DARK)

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
    started = models.DateTimeField(blank=True, null=True)
    completed = models.DateTimeField(blank=True, null=True)
    report_text = models.JSONField()

class Risk(models.Model):
    risk_name = models.CharField(max_length=300)
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    overview_text = models.TextField()
    recommendation_text = models.TextField()
    severity = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(10)])
    affected = models.IntegerField(default=0)
    is_archived = models.BooleanField(default=False)