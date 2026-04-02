# RePortly
Our project is a full-stack web application intended to help schools, small businesses, and nonprofits generate a report to evaluate the security of their organization/network and provide recommendations for reducing their risk of cyber attacks.

## Documentation
- [Figma Design](https://www.figma.com/design/fOgJ1bQrn7GLTxbtucUyiu/RePortly--Cybersecurity-Assessment-Tool?node-id=413-213&t=jcFOd9pt7OnxXOPL-1)

## Key Features
- **User Authentication**: Secure user login and registration.
- **Report Generation**: Generates detailed security report based on user input via a questionnare and network scan. 
- **Gemini API Integration**: Uses Gemini API to provide evaluations and recommendations.
- **Data Persistence**: Stores reports and user data securely in a PostgreSQL database.
- **Intuitive UI/UX**: A response and user-friendly interface built with HTML, Bootstrap, and jQuery/JavaScript.

## Technologies Used
**Frontend**
- HTML / CSS
- Bootstrap
- jQuery / JavaScript

**Backend**
- Django
- Django REST Framework
- Python (3.10.18)
- PostgreSQL
- Django-Q2 (for background tasks/clustering)
- Gemini API
- Pandas, Matplotlib, and PyPDF (for data analysis and report generation)

**Hosting**
- Heroku
- Heroku Postgres
- Gunicorn (WSGI HTTP Server for Production)
- WhiteNoise (for static file serving in Production)

**Email Notification**
- Sendgrid
- Gmail SMTP

# Developer Onboarding and Local Setup
If you are a new developer joining the project, follow these steps to replicate our existing environment on your local machine.

## Prerequisites
Ensure you have the following installed on your local machine:
- [Anaconda](https://www.anaconda.com/download)
- [PostgreSQL](https://www.postgresql.org/download/)
- [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli)
- [A Gemini API Key](https://ai.google.dev/gemini-api/docs/api-key)

## Local Backend Setup
1. Clone the repository
    ```
    git clone [https://github.com/Cybersecurity-Assessment-Tool/Cybersecurity-Assessment-Tool.git](https://github.com/Cybersecurity-Assessment-Tool/Cybersecurity-Assessment-Tool.git)
   cd Cybersecurity-Assessment-Tool
    ```
2. Create an Anaconda environment and activate it:
    ```
    conda create --name <env-name> python=3.10.18
    conda activate <env-name>
    ```
3. Install the required Python packages. We manage our pacakges via pip inside the Conda environment.
    ```
    pip install -r requirements.txt
    ```
4. Configure environment variables
- Create a `.env` file in the `cybersecurity-assessment-tool` directory. (Note: This file is for local development only and is ignored by Git)
- Add your database credentials, Gemini API key, etc:
    ```
    DATABASE_URL=postgres://[user]:[password]@[host]:[port]/[database_name]
    DATABASE_PASSWORD=[Your_PostgreSQL_Database_Password]
    GEMINI_API_KEY=[Your_Gemini_API_Key]
    SECRET_KEY=[Your_Django_Secret_Key]
    SALT_KEY=[Your_Salt_Key]
    DJANGO_ENVIRONMENT=local
    DEBUG=True
    ```
5. Run database migrations
    ```
    cd cybersecurity_assessment_tool
    python manage.py makemigrations
    python manage.py migrate
    ```
6. Start the Django development server and Q cluster:
You will need both processes running to test the web interface and background tasks locally.
**Option 1 — Run both with a single script (recommended)**

*macOS / Linux / Windows (Git Bash or WSL):*
```bash
cd cybersecurity_assessment_tool
./run_dev.sh          # default port 8000
./run_dev.sh 8080     # custom port
```
Press `Ctrl+C` to stop both processes.

*Windows (Command Prompt):*
```bat
cd cybersecurity_assessment_tool
run_dev.bat           # default port 8000
run_dev.bat 8080      # custom port
```
Press any key in the launcher window to shut down both processes.

**Option 2 — Run in two separate terminals**

*Terminal 1 — Django development server:*
```
python manage.py runserver
```

*Terminal 2 — Django Q cluster:*
```
python manage.py qcluster
```

## Frontend Setup
1. Navigate to the directory containing your `package.json` file.
2. Install frontend dependencies:
    ```
    npm install
    ```
3. Compile/watch frontend assets (if applicable based on your project configuration):
    ```
    npm run build
    ```

# Heroku Deployment
This project is configured for deployment on Heroku. The platform handles environment variables, static file collection, and process management differently than a local setup.

## Production Configuration Files
Our repository already contains the necessary files for Heroku deployments.
- `Procfile`: Directs Heroku on how to run the web server, worker, and release tasks.
- `requirements.txt`: Contains all production dependencies (including `gunicorn`, `psycopg2-binary`, `whitenoise`, and `django-q2`).
- `runtime.txt`: Tells Heroku to build the environment using `python-3.10.18`.

## Deploying via Heroku CLI
If you have been granted access to the Heroku app, you can deploy updates. 
1. Ensure you have created an account with the email that has been granted access. Go [here](https://signup.heroku.com/) to create an account.
2. Log in to the Heroku CLI:
    ```
    heroku login
    ```
3. Add the Heroku remote to your local git repository:
    ```
    heroku git:remote -a <your-heroku-app-name>
    ```
4. Provision a PostgreSQL database addon:
    ```
    heroku addons:create heroku-postgresql:<plan>
    ```
5. First-time setup only: Set your production variables. You can also do this in the Heroku dashboard. Note: Heroku automatically sets the `DATABASE_URL` when you provision the Postgres addon.
    ```
    heroku config:set <name-of-env-variable>=<env-variable>
    heroku config:set GEMINI_API_KEY=your_production_api_key
    ```
6. Push your code to Heroku:
    ```
    git push heroku main
    ```
    Heroku will automatically run the `release` commands from the `Procfile` (migrations and collectstatic) during the build.
7. Ensure dynos are running:
    ```
    heroku ps:scale web=1 worker=1
    ```