from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_risk_resolved_at_risk_resolved_by_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='scan_progress',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
