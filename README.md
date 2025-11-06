# Cybersecurity Assessment Tool
Our project is a full-stack web application intended to help schools, small businesses, and nonprofits generate a report to evaluate the security of their organization/network and provide recommendations for reducing their risk of cyber attacks.

## Documentation

## Key Features
- **User Authentication**: Secure user login and registration.
- **Report Generation**: Generates detailed security report based on user input via a questionnare and network scan. 
- **Gemini API Integration**: Uses Gemini API to provide evaluations and recommendations.
- **Data Persistence**: Stores reports and user data securely in a PostgreSQL database.
- **Intuitive UI/UX**: A response and user-friendly interface built with Jquery/JavaScript.

## Technologies Used
**Frontend**
- HTML
- Bootstrap
- JQuery
- JavaScript

**Backend**
- Django
- Django REST Framework
- Python
- PostgreSQL
- Gemini API

**Hosting**
- Heroku

**Email Notification**
- Gmail SMTP

# Installation and Setup
## Prerequisites
Ensure you have the following installed:
- Node.js and npm
- Anaconda
- PostgreSQL
- [A Gemini API Key](https://aistudio.google.com/welcome?utm_source=PMAX&utm_source=PMAX&utm_medium=display&utm_medium=display&utm_campaign=FY25-global-DR-pmax-1710442&utm_campaign=FY25-global-DR-pmax-1710442&utm_content=pmax&utm_content=pmax&gclsrc=aw.ds&gad_source=1&gad_campaignid=21521909442&gbraid=0AAAAACn9t67C4jSAFbC4_60CwHqLfNKPn&gclid=Cj0KCQjw3OjGBhDYARIsADd-uX5Z7iVfAikJYLjQGazBsLPRN2yfgOMdxVg2eMHoWkWtaHs0OxvpJB0aAop3EALw_wcB)

## Backend Setup
1. Clone the repository
2. Create an Anaconda environment and activate it:
3. Install the required Python packages. Inside of the backend folder run:
```
pip install -r requirements.txt
```
4. Configure environment variables
- Create a `.env` file in the `backend` directory.
- Add your database credentials and Gemini API key:
```
DATABASE_URL=postgres://[user]:[password]@[host]:[port]/[database_name]
GEMINI_API_KEY=[Your_Gemini_API_Key]
SECRET_KEY=...
```
5. Run database migrations
```
python manage.py makemigrations
python manage.py migrate
```
6. Start the Django development server:
```
python manage.py runserver
```

## Frontend Setup

# Usage
