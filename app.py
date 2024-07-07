import os
from datetime import datetime
from flask import Flask, session, abort, render_template, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
import requests
import google.auth.transport.requests
from pip._vendor import cachecontrol
from google.oauth2 import id_token
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from apscheduler.schedulers.background import BackgroundScheduler

# Load environment variables from .env file
load_dotenv()

app = Flask("__name__")
app.secret_key = os.environ.get("SECRET_KEY", "default_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:5000/callback")

client_config = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "project_id": "deadlineguardian",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uris": [REDIRECT_URI]
    }
}

flow = Flow.from_client_config(
    client_config,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=REDIRECT_URI
)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    reminder = db.Column(db.DateTime, nullable=True)  # Add reminder field

def login_is_required(function):
    def wrapper_function(*args, **kwargs):
        print("Checking if user is logged in...")
        if "google_id" not in session:
            print("User not logged in.")
            return abort(401)  # Authorization required
        else:
            print("User is logged in.")
            return function(*args, **kwargs)
    wrapper_function.__name__ = function.__name__
    return wrapper_function

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    print(f"Login state set: {state}")
    print(f"Session after setting state: {session}")
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    state_in_session = session.get("state")
    state_in_request = request.args.get("state")
    print(f"Session at callback: {session}")
    if not state_in_session:
        print("No state in session.")
        abort(500)
    if state_in_session != state_in_request:
        print(f"State mismatch: {state_in_session} != {state_in_request}")
        abort(500)

    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        print(f"Error fetching token: {e}")
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    try:
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )
    except Exception as e:
        print(f"Error verifying ID token: {e}")
        abort(500)

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("given_name")
    session["email"] = id_info.get("email")
    print(f"User logged in: {session['email']}")
    return redirect('/protected_area')

@app.route("/logout")
def logout():
    session.clear()
    return redirect('/')

@app.route("/")
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"

@app.route("/protected_area")
@login_is_required
def protected_area():
    tasks = Task.query.filter_by(email=session['email']).all()
    return render_template('add_task.html', tasks=tasks)

@app.route('/add_task', methods=['POST'])
@login_is_required
def add_task():
    task_content = request.form['content']
    reminder_time = request.form.get('reminder')
    if reminder_time:
        reminder_time = datetime.strptime(reminder_time, '%Y-%m-%dT%H:%M')
    new_task = Task(task=task_content, email=session['email'], reminder=reminder_time)
    db.session.add(new_task)
    db.session.commit()
    if reminder_time:
        schedule_email(session['email'], 'Task Reminder', f'Reminder for your task: {task_content}', reminder_time)
    return redirect('/protected_area')

@app.route('/delete_task/<int:id>')
@login_is_required
def delete_task(id):
    task_to_delete = Task.query.get_or_404(id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect('/protected_area')

def send_email(to_email, subject, body):
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")

    msg = MIMEMultipart()
    msg['From'] = smtp_username
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)
    text = msg.as_string()
    server.sendmail(smtp_username, to_email, text)
    print("email was sent")
    server.quit()

scheduler = BackgroundScheduler()
scheduler.start()

def schedule_email(to_email, subject, body, send_time):
    scheduler.add_job(
        send_email,
        'date',
        run_date=send_time,
        args=[to_email, subject, body]
    )

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
