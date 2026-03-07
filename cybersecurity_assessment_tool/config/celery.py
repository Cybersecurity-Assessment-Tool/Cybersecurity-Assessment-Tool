import os
import sys
from pathlib import Path
from celery import Celery

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cybersecurity_assessment_tool.config.settings')

app = Celery('cybersecurity_assessment_tool')

# Load task modules from all registered Django app configs.
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()