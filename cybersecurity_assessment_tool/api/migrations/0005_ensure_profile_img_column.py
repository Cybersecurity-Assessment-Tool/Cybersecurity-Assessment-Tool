from django.db import migrations, models
import api.models


def ensure_profile_img_column(apps, schema_editor):
    """Keep the user profile image column compatible with existing databases."""
    table_name = 'api_user'
    connection = schema_editor.connection
    quote = schema_editor.quote_name

    with connection.cursor() as cursor:
        columns = {
            column.name
            for column in connection.introspection.get_table_description(cursor, table_name)
        }

    if 'profile_img' in columns:
        return

    if 'profile_image' in columns:
        schema_editor.execute(
            f"ALTER TABLE {quote(table_name)} RENAME COLUMN {quote('profile_image')} TO {quote('profile_img')}"
        )
        return

    schema_editor.execute(
        f"ALTER TABLE {quote(table_name)} ADD COLUMN {quote('profile_img')} varchar(100) NULL"
    )


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_alter_invitation_recipient_role_and_more'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(ensure_profile_img_column, migrations.RunPython.noop),
            ],
            state_operations=[
                migrations.AlterField(
                    model_name='user',
                    name='profile_image',
                    field=models.ImageField(
                        blank=True,
                        db_column='profile_img',
                        null=True,
                        upload_to=api.models.User.profile_image_path,
                    ),
                ),
            ],
        ),
    ]
