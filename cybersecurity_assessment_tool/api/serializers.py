from rest_framework import serializers
from .models import Organization, User, Report, Risk, Color, Frequency

class OrganizationSerializer(serializers.ModelSerializer):
    """
    Serializer for the Organization model.
    organization_id is read-only.
    """
    class Meta:
        model = Organization
        fields = '__all__'
        read_only_fields = ('organization_id',)
        
class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the custom User model.
    organization is represented by its primary key (UUID).
    We exclude the password from being displayed on read operations.
    """
    # use StringRelatedField to display the organization name instead of just the UUID
    organization_name = serializers.ReadOnlyField(source='organization.org_name')
    
    class Meta:
        model = User
        # include all fields except the sensitive ones we'll handle manually
        fields = [
            'user_id', 'username', 'email', 'first_name', 'last_name', 
            'is_staff', 'is_active', 'date_joined', 'last_login',
            'organization', 'organization_name', 
            'is_automated', 'auto_frequency', 'profile_img', 
            'font_size', 'color', 
            'groups', 'user_permissions'
        ]
        # these fields are read-only after creation or are for internal use
        read_only_fields = ('user_id', 'is_staff', 'is_active', 'date_joined', 'last_login', 'organization_name')
        # exclude password from the API response
        extra_kwargs = {'password': {'write_only': True}}
        
    def create(self, validated_data):
        """Handle password hashing during user creation."""
        user = User.objects.create_user(**validated_data)
        return user

class ReportSerializer(serializers.ModelSerializer):
    """
    Serializer for the Report model.
    Foreign key fields are read-only and display the related object's string representation.
    """
    # display the username and organization name instead of just IDs
    user_created_name = serializers.ReadOnlyField(source='user_created.username')
    organization_name = serializers.ReadOnlyField(source='organization.org_name')
    
    class Meta:
        model = Report
        fields = '__all__'
        read_only_fields = ('report_id', 'date_created', 'user_created_name', 'organization_name')

class RiskSerializer(serializers.ModelSerializer):
    """
    Serializer for the Risk model.
    report is represented by its primary key (UUID).
    """
    # display the report name for context
    report_name = serializers.ReadOnlyField(source='report.report_name')

    class Meta:
        model = Risk
        fields = '__all__'
        # the 'severity' field uses validators defined in the model.