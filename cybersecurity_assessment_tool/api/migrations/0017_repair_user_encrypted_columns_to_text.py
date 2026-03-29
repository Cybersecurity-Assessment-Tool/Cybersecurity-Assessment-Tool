from django.db import migrations


def repair_user_encrypted_columns(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return

    table_name = 'api_user'
    target_columns = ('email', 'first_name', 'last_name', 'password')

    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            """,
            [table_name],
        )
        column_types = {name: data_type for name, data_type in cursor.fetchall()}

    for column in target_columns:
        if column_types.get(column) != 'text':
            schema_editor.execute(
                f'ALTER TABLE {table_name} ALTER COLUMN {column} TYPE text'
            )


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0016_repair_missing_organization_columns'),
    ]

    operations = [
        migrations.RunPython(repair_user_encrypted_columns, migrations.RunPython.noop),
    ]
