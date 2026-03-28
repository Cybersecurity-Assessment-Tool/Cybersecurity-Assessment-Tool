import hashlib
from django.db import models
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver
import os

User = get_user_model()

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
    salted_email = f"{normalized_email}{SECRET_KEY}"
    
    # 3. Generate and return the SHA-256 hex digest (64 characters)
    return hashlib.sha256(salted_email.encode('utf-8')).hexdigest()

def profile_image_path(instance, filename):
    """Generate file path for new profile image"""
    ext = filename.split('.')[-1]
    filename = f"profile_{instance.user.username}_{instance.user.id}.{ext}"
    return os.path.join('uploads/profile_images/', filename)

class UserProfile(models.Model):
    """
    Extended user profile model to store additional user preferences
    and settings that aren't in the built-in User model.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Basic Information
    display_name = models.CharField(max_length=100, blank=True, help_text="Name displayed to other users")
    profile_image = models.ImageField(upload_to=profile_image_path, blank=True, null=True)
    # job_title = models.CharField(max_length=100, blank=True)
    # phone_number = models.CharField(max_length=20, blank=True)
    # timezone = models.CharField(max_length=50, default='UTC')
    
    # Notification Preferences
    # email_notifications = models.BooleanField(default=True, help_text="Receive email notifications")
    # email_on_critical = models.BooleanField(default=True, help_text="Email when critical vulnerabilities found")
    # email_on_scan_complete = models.BooleanField(default=True, help_text="Email when scans complete")
    # email_digest = models.CharField(
    #     max_length=10,
    #     choices=[
    #         ('immediate', 'Immediate'),
    #         ('daily', 'Daily Digest'),
    #         ('weekly', 'Weekly Digest'),
    #     ],
    #     default='immediate'
    # )
    
    # Display Preferences
    # items_per_page = models.IntegerField(default=25, choices=[(10,10), (25,25), (50,50), (100,100)])
    # default_view = models.CharField(
    #     max_length=20,
    #     choices=[
    #         ('dashboard', 'Dashboard'),
    #         ('scans', 'Recent Scans'),
    #         ('vulnerabilities', 'Vulnerability List'),
    #     ],
    #     default='dashboard'
    # )
    
    # Organization (will be linked later)
    organization_role = models.CharField(
        max_length=20,
        choices=[
            ('admin', 'Administrator'),
            ('analyst', 'Security Analyst'),
            ('viewer', 'Viewer'),
            ('auditor', 'Auditor'),
        ],
        default='viewer',
        help_text="User's role in the organization"
    )
    
    # Metadata
    # created_at = models.DateTimeField(auto_now_add=True)
    # updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
    
    def __str__(self):
        return f"Profile for {self.user.username}"
    
    def get_display_name(self):
        """Return display name or fall back to username"""
        return self.display_name or self.user.username

# Signal to automatically create/update profile when User is created/updated
@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """Create a profile for every new user automatically"""
    if created:
        UserProfile.objects.create(user=instance)
    else:
        # For existing users, save profile if it exists
        if hasattr(instance, 'profile'):
            instance.profile.save()