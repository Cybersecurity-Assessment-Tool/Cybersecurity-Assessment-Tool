from django.db import migrations, models
from django.utils import timezone


def add_missing_organization_columns(apps, schema_editor):
    Organization = apps.get_model('api', 'Organization')
    table_name = Organization._meta.db_table

    with schema_editor.connection.cursor() as cursor:
        existing_columns = {
            column.name
            for column in schema_editor.connection.introspection.get_table_description(cursor, table_name)
        }

    def add_field(field):
        field.set_attributes_from_name(field.name)
        schema_editor.add_field(Organization, field)

    if 'questionnaire_completed' not in existing_columns:
        add_field(models.BooleanField(name='questionnaire_completed', default=False))

    if 'registration_status' not in existing_columns:
        add_field(
            models.CharField(
                name='registration_status',
                max_length=20,
                choices=[
                    ('pending', 'Pending Approval'),
                    ('approved', 'Approved'),
                    ('rejected', 'Rejected'),
                ],
                default='pending',
            )
        )

    if 'created_at' not in existing_columns:
        add_field(models.DateTimeField(name='created_at', default=timezone.now))

    if 'approved_at' not in existing_columns:
        add_field(models.DateTimeField(name='approved_at', null=True, blank=True))


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_alter_otpverification_expires_at'),
    ]

    operations = [
        migrations.RunPython(add_missing_organization_columns, migrations.RunPython.noop),
    ]
