release: cd cybersecurity_assessment_tool && python manage.py migrate --noinput && python manage.py collectstatic --noinput
web: gunicorn config.wsgi --chdir cybersecurity_assessment_tool --log-file -
