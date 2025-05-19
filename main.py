
import logging
import os
import platform
import secrets
import subprocess
import time
import uuid
from datetime import datetime, timedelta

from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from textblob import TextBlob
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from wtforms import SubmitField, TextAreaField, StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)  # Enable SQLAlchemy logging
logger = logging.getLogger(__name__)

# Attempt to import g4f.client with fallback
try:
    from g4f.client import Client
except ImportError as e:
    logger.warning(f"Failed to import g4f.client: {str(e)}. AI features will be disabled.")
    Client = None
from flask_wtf.file import FileField, FileRequired, FileAllowed

# Start Chrome with remote debugging (optional, commented out due to missing Chrome)
def start_chrome():
    chrome_paths = {
        'Windows': r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        'Linux': '/usr/bin/google-chrome',
        'Darwin': '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    }
    chrome_path = os.environ.get('CHROME_PATH', chrome_paths.get(platform.system(), 'google-chrome'))
    port = 9222
    try:
        result = subprocess.run(['netstat', '-a', '-n', '-o'] if platform.system() == 'Windows' else ['lsof', '-i', f':{port}'],
                               capture_output=True, text=True, check=False)
        if (platform.system() == 'Windows' and f":{port}" not in result.stdout) or \
           (platform.system() != 'Windows' and result.returncode != 0):
            user_data_dir = r"C:\Temp\ChromeDebugProfile" if platform.system() == 'Windows' else "/tmp/ChromeDebugProfile"
            os.makedirs(user_data_dir, exist_ok=True)
            subprocess.Popen([
                chrome_path,
                f"--remote-debugging-port={port}",
                f"--user-data-dir={user_data_dir}"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"Started Chrome with remote debugging on port {port}")
            time.sleep(2)
        else:
            logger.info(f"Chrome already running on port {port}")
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError) as e:
        logger.warning(f"Failed to start Chrome: {str(e)}. Continuing without Chrome debugging.")

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(24))

# Set up instance directory and database URI with absolute path
instance_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
os.makedirs(instance_path, exist_ok=True)
# Ensure the instance directory is writable
os.chmod(instance_path, 0o700)  # Restrict to owner only
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "project_ideas.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please login to access this page.'

g4f_client = Client() if Client else None

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Forms
class FeedbackForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit Feedback')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Regexp('^[a-zA-Z0-9]+$', message='Username must be alphanumeric.')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, message='Password must be at least 8 characters.'), Regexp('.*[A-Z].*', message='Password must contain an uppercase letter.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Username is required.')])
    password = PasswordField('Password', validators=[DataRequired(message='Password is required.')])
    submit = SubmitField('Login')

class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20), Regexp('^[a-zA-Z0-9]+$', message='Username must be alphanumeric')])
    is_admin = BooleanField('Admin')
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6), Regexp('^(?=.*[A-Z])', message='Password must contain at least one uppercase letter.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Create User')

class AddProjectForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    idea = TextAreaField('Idea', validators=[DataRequired()])
    image = FileField('Image')
    submit = SubmitField('Add Project')

class EditProjectForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    idea = TextAreaField('Idea')
    image = FileField('Image')
    submit = SubmitField('Update Project')

class EditGroupForm(FlaskForm):
    name = StringField('Group Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Update Group')

class CreateGroupForm(FlaskForm):
    name = StringField('Group Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    image = FileField('Group Image', validators=[FileAllowed(['jpg', 'png', 'gif', 'jpeg'], 'Images only!')])

class MessageForm(FlaskForm):
 content = TextAreaField('Message Content')
 image = FileField('Image', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')])
 audio = FileField('Audio', validators=[FileAllowed(['wav', 'mp3', 'ogg'], 'Audio files only!')])
 sticker = StringField('Sticker') # Assuming sticker is a string identifier

# Educational AI Assistant Class
class EducationalAIAssistant:
    def __init__(self):
        self.client = Client() if Client else None

    def get_response(self, user_message):
        if not self.client:
            return "Error: AI features are currently unavailable. Try prompts like 'Create a math learning app' or contact support."
        try:
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an educational AI assistant designed exclusively for students. "
                        "Your responses must strictly pertain to academic, educational, or study-related topics. "
                        "Generate technology project ideas suitable for educational purposes. "
                        "Avoid any conversation or content that is not directly related to education."
                    )
                },
                {"role": "user", "content": user_message}
            ]
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=messages,
                web_search=False
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error in get_response: {str(e)}")
            return f"Error: Unable to generate response. Try specific prompts like 'biology app' or 'physics simulation'."

    def handle_educational_query(self, query):
        try:
            response = self.get_response(f"Generate a technology project idea based on: {query}")
            return {"response": response}
        except Exception as e:
            logger.error(f"Error in handle_educational_query: {str(e)}")
            return {"response": f"Error: Unable to generate idea. Try prompts like 'biology app' or 'physics simulation'."}

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    projects = db.relationship('Project', backref='creator', lazy=True)
    votes = db.relationship('Vote', backref='user', lazy=True)
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)
    created_groups = db.relationship('Group', backref='creator', lazy=True)
    group_memberships = db.relationship('GroupMembership', backref='user', lazy=True)
    messages = db.relationship('Message', backref='user', lazy=True)
    message_read_statuses = db.relationship('MessageReadStatus', backref='user', lazy=True)
    created_invites = db.relationship('GroupInvite', backref='creator', lazy=True)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Project(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    idea = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    votes = db.relationship('Vote', backref='project', lazy=True)
    feedbacks = db.relationship('Feedback', backref='project', lazy=True)

class Vote(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.String(36), db.ForeignKey('project.id'), nullable=False)
    is_like = db.Column(db.Boolean, nullable=False)

class Feedback(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.String(36), db.ForeignKey('project.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    sentiment = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    message_type = db.Column(db.String(20), default='text', nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    read_statuses = db.relationship('MessageReadStatus', backref='message', lazy=True)
    message_votes = db.relationship('MessageVote', backref='message', lazy=True)

class MessageReadStatus(db.Model):
    __tablename__ = 'message_read_status'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    message_id = db.Column(db.String(36), db.ForeignKey('message.id'), nullable=False)
    read_at = db.Column(db.DateTime, nullable=True)
    __table_args__ = (db.UniqueConstraint('user_id', 'message_id', name='_user_message_uc'),)

class MessageVote(db.Model):
    __tablename__ = 'message_vote'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    message_id = db.Column(db.String(36), db.ForeignKey('message.id'), nullable=False)
    vote_type = db.Column(db.String(20), nullable=False)  # e.g., 'upvote', 'downvote'
    __table_args__ = (db.UniqueConstraint('user_id', 'message_id', name='_user_message_vote_uc'),)

class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    creator_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    members = db.relationship('GroupMembership', backref='group', lazy=True)
    messages = db.relationship('Message', backref='group', lazy=True,
                               primaryjoin='Group.id == Message.group_id',
                               foreign_keys=[Message.group_id])
    invites = db.relationship('GroupInvite', backref='group', lazy=True)

class GroupMembership(db.Model):
    __tablename__ = 'group_membership'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'group_id', name='_user_group_uc'),)

class GroupInvite(db.Model):
    __tablename__ = 'group_invite'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    creator_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    max_uses = db.Column(db.Integer, nullable=True, default=None)
    uses = db.Column(db.Integer, default=0, nullable=False)

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = FeedbackForm()
    featured_projects = Project.query.order_by(Project.created_at.desc()).limit(3).all()
    user = None
    return render_template('home.html', featured_projects=featured_projects, form=form, user=user)

@app.route('/home')
def home():
    form = FeedbackForm()
    featured_projects = Project.query.order_by(Project.created_at.desc()).limit(3).all()
    user = current_user if current_user.is_authenticated else None
    return render_template('home.html', featured_projects=featured_projects, form=form, user=user)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        user = User(username=username)
        user.password = password

        try:
            logger.debug(f"Attempting to add user {username} to session.")
            db.session.add(user)
            db.session.commit()
            logger.debug("User saved to database.")
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error during registration for user {username}: {e}", exc_info=True)
            flash(f'An error occurred during registration: {e}. Please try again.', 'error')
    else:
        for field, errors in form.errors.items():
            flash(f'Error in {field}: {", ".join(errors)}', 'danger')
            logger.debug(f"Field: {field}, Errors: {errors}")
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    user = None # Initialize user to None
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        logger.info(f"Login attempt for username: {username}")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            logger.info(f"User {username} logged in successfully.")
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    else:
        logger.warning(f"Login failed for username: {form.username.data}. Invalid credentials.")
    flash('Invalid username or password.', 'error')
    return render_template('login.html', form=form)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if username == 'admin' and password == 'admin123':
            admin_user = User.query.filter_by(username='admin').first() # Fetch admin user to log in
            login_user(admin_user)
            flash('Admin login successful! Welcome to the Admin Dashboard.', 'success')            
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin credentials.', 'error')
    return render_template('admin_login.html', form=form)

@app.route('/admin')
@login_required
def admin(): 
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    user_count = User.query.count()
    project_count = Project.query.count()
    feedback_count = Feedback.query.count()
    recent_feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).limit(5).all()
    return render_template('admin.html', user_count=user_count, project_count=project_count,
                          feedback_count=feedback_count, recent_feedbacks=recent_feedbacks)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user
    projects = Project.query.filter_by(user_id=user.id).all()
    user_groups = [m.group for m in GroupMembership.query.filter_by(user_id=user.id).all()]
    unread_counts = {}
    for group in user_groups:
        unread_count = Message.query.filter(
            Message.group_id == group.id,
            ~Message.read_statuses.any(
                db.and_(
                    MessageReadStatus.user_id == user.id,
                    MessageReadStatus.read_at != None
                )
            )
        ).count()
        unread_counts[group.id] = unread_count
    project_data = []
    all_feedbacks = []
    for project in projects:
        feedbacks = Feedback.query.filter_by(project_id=project.id).all()
        like_count = Vote.query.filter_by(project_id=project.id, is_like=True).count()
        unlike_count = Vote.query.filter_by(project_id=project.id, is_like=False).count()
        feedback_count = len(feedbacks)
        project_data.append({
            'project': project,
            'feedbacks': feedbacks,
            'like_count': like_count,
            'unlike_count': unlike_count,
            'feedback_count': feedback_count
        })
        all_feedbacks.extend(feedbacks)
    return render_template('dashboard.html', user=user, projects=projects,
                          project_data=project_data, all_feedbacks=all_feedbacks,
                          user_groups=user_groups, unread_counts=unread_counts)

@app.route('/manage_users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    form = CreateUserForm()
    if form.validate_on_submit():
        username = form.username.data
        existing_user = User.query.filter(
            User.username == username, User.id != user_id
        ).first()
        if existing_user:
            flash('Username already exists.', 'error')
            return redirect(url_for('edit_user', user_id=user_id))
        user.username = username
        user.is_admin = form.is_admin.data
        if form.password.data:
            user.password = form.password.data
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('manage_users'))
    form.username.data = user.username
    form.is_admin.data = user.is_admin
    return render_template('edit_user.html', user=user, form=form)

@app.route('/admin/delete_user/<user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    form = CreateUserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'warning')
            return render_template('create_user.html', form=form)
        user = User(username=username, is_admin=form.is_admin.data)
        user.password = password
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('manage_users'))
    return render_template('create_user.html', form=form)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/add_project', methods=['GET', 'POST'])
@login_required
def add_project():
    form = AddProjectForm()
    image_path = None  # Initialize image_path to None
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        idea = form.idea.data
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = f"uploads/{filename}"
        existing_project = Project.query.filter_by(title=title, user_id=current_user.id).first()
        if existing_project:
            flash('You already have a project with this title.', 'error')
            return redirect(url_for('add_project'))
        project = Project(

            title=title,
            description=description,
            idea=idea,
            image=image_path,
            user_id=current_user.id
        )
        db.session.add(project)
        db.session.commit()
        flash('Project added successfully!', 'success')
        return redirect(url_for('dashboard')) # Redirect to dashboard after successful submission

    return render_template('add_project.html', form=form)
@app.route('/edit_project/<project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    form = EditProjectForm()
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        idea = form.idea.data
        existing_project = Project.query.filter(
            Project.title == title, Project.user_id == current_user.id, Project.id != project_id
        ).first()
        if existing_project:
            flash('You already have a project with this title.', 'error')
            return redirect(url_for('edit_project', project_id=project_id))
        project.title = title
        project.description = description
        project.idea = idea
        logger.debug(f"Attempting to save file from request.files: {'image' in request.files}")

        # Handle image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                project.image = f"uploads/{filename}"
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.title.data = project.title
        form.description.data = project.description
        form.idea.data = project.idea
    return render_template('edit_project.html', form=form, project=project)

@app.route('/delete_project/<project_id>')
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/vote/<project_id>/<action>')
@login_required
def vote(project_id, action):
    project = Project.query.get_or_404(project_id)
    existing_vote = Vote.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if existing_vote:
        if existing_vote.is_like == (action == 'like'):
            flash('You have already voted this way.', 'error')
            return redirect(request.referrer or url_for('index'))
        db.session.delete(existing_vote)
    if action != 'remove':
        vote = Vote(
            user_id=current_user.id,
            project_id=project_id,
            is_like=(action == 'like')
        )
        db.session.add(vote)
    db.session.commit()
    flash(f'Project {"liked" if action == "like" else "unliked"} successfully!', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/feedback/<project_id>', methods=['POST'])
@login_required
def feedback(project_id):
    form = FeedbackForm()
    if form.validate_on_submit():
        try:
            comment = form.comment.data
            existing_feedback = Feedback.query.filter_by(user_id=current_user.id, project_id=project_id).first()
            if existing_feedback:
                flash('You have already submitted feedback for this project.', 'error')
                return redirect(url_for('index') + f'#project-{project_id}')
            analysis = TextBlob(comment)
            polarity = analysis.sentiment.polarity
            sentiment = 'positive' if polarity > 0.1 else 'negative' if polarity < -0.1 else 'neutral'
            feedback = Feedback(
                user_id=current_user.id,
                project_id=project_id,
                comment=comment,
                sentiment=sentiment
            )
            db.session.add(feedback)
            db.session.commit()
            flash('Feedback submitted successfully!', 'success')
            return redirect(url_for('index') + f'#project-{project_id}')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Feedback submission failed: {str(e)}")
            flash('Failed to submit feedback. Please try again.', 'error')
    else:
        logger.error(f"Form validation errors: {form.errors}")
        flash('Invalid feedback submission. Please check your input.', 'error')
    return redirect(url_for('index') + f'#project-{project_id}')

@app.route('/generate_idea', methods=['POST'])
@limiter.limit("5 per minute")
@login_required
def generate_idea():
    prompt = request.form.get('prompt')
    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400
    try:
        assistant = EducationalAIAssistant()
        result = assistant.handle_educational_query(prompt)
        return jsonify({'idea': result['response']})
    except Exception as e:
        logger.error(f"Error in generate_idea: {str(e)}")
        return jsonify({'error': f"Failed to generate idea: {str(e)}. Try prompts like 'biology app' or 'physics simulation'."}), 500

@app.route('/chatbot', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@login_required
def chatbot():
    if request.method == 'POST':
        message = request.form.get('message')
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        if not g4f_client:
            return jsonify({'error': 'AI client not available. Ensure g4f is installed.'}), 500
        try:
            response = g4f_client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": f"Discuss project implementation for an educational project: {message}"}]
            )
            reply = response.choices[0].message.content
            return jsonify({'reply': reply})
        except Exception as e:
            logger.error(f"Error in chatbot: {str(e)}")
            return jsonify({'error': f"Failed to fetch response: {str(e)}. Ask about implementing an educational project, e.g., 'math game'."}), 500
    return render_template('chatbot.html')

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    form = CreateGroupForm()
    if request.method == 'POST':
        form = CreateGroupForm(request.form)
        logger.debug(f"Form name data: {form.name.data}")
        logger.debug(f"Form validate_on_submit: {form.validate_on_submit()}")
        logger.debug(f"Form errors: {form.errors}")
        group_name = form.name.data
        group_description = form.description.data
        if not group_name:
            flash('Group name is required.', 'error')
            return redirect(url_for('create_group'))
        existing_group = Group.query.filter_by(name=group_name, creator_id=current_user.id).first()
        if existing_group:
            flash('You already created a group with this name.', 'error')
            return redirect(url_for('create_group'))
        try:
            group = Group(
                name=group_name,
                description=group_description,
                creator_id=current_user.id
            )
            # Handle image upload
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    group.image = f"uploads/{filename}"
            db.session.add(group)
            db.session.commit()
            membership = GroupMembership(
                user_id=current_user.id,
                group_id=group.id
            )
            db.session.add(membership)
            token = secrets.token_urlsafe(32)
            invite = GroupInvite(
                group_id=group.id,
                token=token,
                creator_id=current_user.id,
                expires_at=datetime.utcnow() + timedelta(days=7),
                max_uses=10,
                uses=0
            )
            db.session.add(invite)
            db.session.commit()
            invite_link = f"{request.url_root}invite/{token}"
            flash(f'Group created successfully! Invite link: {invite_link}', 'success')
            return redirect(url_for('view_groups'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create group: {str(e)}")
            flash('Failed to create group. Please try again.', 'error')
            return redirect(url_for('create_group'))
    return render_template('create_group.html', form=form)

@app.route('/groups')
@login_required
def view_groups():
    user = current_user
    groups = Group.query.all()
    user_groups = [m.group_id for m in GroupMembership.query.filter_by(user_id=user.id).all()]
    unread_counts = {}
    for group in groups:
        unread_count = Message.query.filter(
            Message.group_id == group.id,
            ~Message.read_statuses.any(
                db.and_(
                    MessageReadStatus.user_id == user.id,
                    MessageReadStatus.read_at != None
                )
            )
        ).count()
        unread_counts[group.id] = unread_count
    invites = {}
    for group in groups:
        if group.creator_id == user.id:
            invite = GroupInvite.query.filter_by(group_id=group.id).first()
            if invite and invite.expires_at > datetime.utcnow() and (invite.max_uses is None or invite.uses < invite.max_uses):
                invites[group.id] = f"{request.url_root}invite/{invite.token}"
    return render_template('groups.html', groups=groups, user_groups=user_groups, user=user,
                          unread_counts=unread_counts, invites=invites)

@app.route('/join_group/<group_id>')
@login_required
def join_group(group_id):
    group = Group.query.get_or_404(group_id)
    existing_membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if existing_membership:
        flash('You are already a member of this group.', 'error')
    else:
        membership = GroupMembership(
            user_id=current_user.id,
            group_id=group_id
        )
        db.session.add(membership)
        db.session.commit()
        flash('Joined group successfully!', 'success')
    return redirect(url_for('view_groups'))

@app.route('/edit_group/<group_id>', methods=['GET', 'POST'])
@login_required
def edit_group(group_id):
    group = Group.query.get_or_404(group_id)
    if group.creator_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('view_groups'))

    form = EditGroupForm()

    if form.validate_on_submit():
        group_name = form.name.data
        group_description = form.description.data

        group.name = group_name
        group.description = group_description

        db.session.commit()
        flash('Group updated successfully!', 'success')
        return redirect(url_for('view_groups'))

    elif request.method == 'GET':
        form.name.data = group.name
        form.description.data = group.description

    return render_template('edit_group.html', form=form, group=group)
@app.route('/invite/<token>')
@login_required
def join_group_by_invite(token):
    invite = GroupInvite.query.filter_by(token=token).first()
    if not invite:
        flash('Invalid or expired invite link.', 'error')
        return redirect(url_for('view_groups'))
    if invite.expires_at < datetime.utcnow():
        flash('This invite link has expired.', 'error')
        return redirect(url_for('view_groups'))
    if invite.max_uses is not None and invite.uses >= invite.max_uses:
        flash('This invite link has reached its usage limit.', 'error')
        return redirect(url_for('view_groups'))
    group = Group.query.get_or_404(invite.group_id)
    existing_membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group.id).first()
    if existing_membership:
        flash('You are already a member of this group.', 'error')
        return redirect(url_for('view_groups'))
    try:
        membership = GroupMembership(
            user_id=current_user.id,
            group_id=group.id
        )
        invite.uses += 1
        db.session.add(membership)
        db.session.commit()
        flash(f'Joined group "{group.name}" successfully!', 'success')
        return redirect(url_for('group_chat', group_id=group.id))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to join group via invite: {str(e)}")
        flash('Failed to join group. Please try again.', 'error')
        return redirect(url_for('view_groups'))

@app.route('/leave_group/<group_id>')
@login_required
def leave_group(group_id):
    group = Group.query.get_or_404(group_id)
    if group.creator_id == current_user.id:
        flash('You cannot leave a group you created.', 'error')
        return redirect(url_for('view_groups'))
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash('You are not a member of this group.', 'error')
        return redirect(url_for('view_groups'))
    try:
        db.session.delete(membership)
        db.session.commit()
        flash('Left group successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to leave group: {str(e)}")
        flash('Failed to leave group. Please try again.', 'error')
    return redirect(url_for('view_groups'))

@app.route('/group_chat/<group_id>', methods=['GET', 'POST'])
@login_required
def group_chat(group_id):
    form = MessageForm() # Create an instance of the MessageForm
    group = Group.query.get_or_404(group_id)
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash('You are not a member of this group.', 'error')
        return redirect(url_for('view_groups'))

    # Handle message submission
    
    if form.validate_on_submit():
        # If form is valid on POST, process message and redirect
        # This block handles the case where a message is successfully submitted
        content = form.content.data
        message_type = request.form.get('message_type', 'text')
        if not content and message_type == 'text':
            flash('Message content cannot be empty.', 'error')
            return redirect(url_for('group_chat', group_id=group_id))
        message = Message(
            user_id=current_user.id,
            group_id=group_id,
            content=content,
            message_type=message_type
        )
        db.session.add(message)
        db.session.commit()
        members = GroupMembership.query.filter_by(group_id=group_id).all()
        # Mark message as unread for all members except the sender
        for member in members:
            if member.user_id != current_user.id:
                read_status = MessageReadStatus(
                    user_id=member.user_id,
                    message_id=message.id,
                    read_at=None
                )
                db.session.add(read_status)
        db.session.commit()
        return redirect(url_for('group_chat', group_id=group_id))

    messages = Message.query.filter_by(group_id=group_id).order_by(Message.created_at.asc()).all()

    # Fetch group members
    group_memberships = GroupMembership.query.filter_by(group_id=group_id).all()
    members = [membership.user for membership in group_memberships]

    user = current_user

    # Mark messages as read when the page is loaded (GET request)
    for message in messages:
        read_status = MessageReadStatus.query.filter_by(
            user_id=user.id,
            message_id=message.id
        ).first()
        if not read_status:
            read_status = MessageReadStatus(
                user_id=user.id,
                message_id=message.id,
                read_at=datetime.utcnow()
            )
            db.session.add(read_status)
        elif read_status.read_at is None:
            read_status.read_at = datetime.utcnow()
    db.session.commit()

    return render_template('group_chat.html', group=group, messages=messages, user=user, members=members, form=form) # Ensure template is rendered for GET requests or invalid POST

@app.route('/delete_message/<message_id>', methods=['DELETE'])
@login_required
def delete_message(message_id):
 message = Message.query.get(message_id)
 if not message:
    return jsonify({'success': False, 'error': 'Message not found'}), 404

 if message.user_id != current_user.id:
    return jsonify({'success': False, 'error': 'Unauthorized'}), 403

 try:
    db.session.delete(message)
    db.session.commit()
    return jsonify({'success': True}), 200
 except Exception as e:
    db.session.rollback() # Rollback the transaction in case of error
 return jsonify({'success': False, 'error': 'An error occurred while deleting the message.'}), 500 # Return a JSON error response
@app.route('/vote_message/<message_id>/<string:vote_type>', methods=['POST'])
@login_required
def vote_message(message_id, vote_type):
    if vote_type not in ['upvote', 'downvote']:
        return jsonify({'success': False, 'error': 'Invalid vote type'}), 400
    user_id = current_user.id
    message = Message.query.get(message_id)
    if not message:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    existing_vote = MessageVote.query.filter_by(user_id=user_id, message_id=message_id).first()
    if existing_vote:
        return jsonify({'success': False, 'error': 'You have already voted on this message'}), 409
    new_vote = MessageVote(user_id=user_id, message_id=message_id, vote_type=vote_type)
    db.session.add(new_vote)
    db.session.commit()
    upvote_count = MessageVote.query.filter_by(message_id=message_id, vote_type='upvote').count()
    downvote_count = MessageVote.query.filter_by(message_id=message_id, vote_type='downvote').count()
    return jsonify({'success': True, 'upvote_count': upvote_count, 'downvote_count': downvote_count})

@app.route('/unread_messages')
@login_required
def unread_messages():
    user_id = current_user.id
    unread_counts = db.session.query(
        Message.group_id,
        db.func.count(Message.id).label('unread_count')
    ).outerjoin(
        MessageReadStatus,
        db.and_(
            MessageReadStatus.message_id == Message.id,
            MessageReadStatus.user_id == user_id,
            MessageReadStatus.read_at != None
        )
    ).filter(
        MessageReadStatus.id == None,
        Message.group_id.in_(
            db.session.query(GroupMembership.group_id).filter_by(user_id=user_id)
        )
    ).group_by(Message.group_id).all()
    unread_counts_dict = {group_id: count for group_id, count in unread_counts}
    total_unread = sum(unread_counts_dict.values())
    return jsonify({'unread_counts': unread_counts_dict, 'total_unread': total_unread})

@app.cli.command('generate-suggestions')
def generate_suggestions():
    groups = Group.query.all()
    assistant = EducationalAIAssistant()
    for group in groups:
        recent_messages = Message.query.filter_by(group_id=group.id).order_by(
            Message.created_at.desc()).limit(50).all()
        if not recent_messages:
            continue
        content = " ".join([msg.content for msg in recent_messages if msg.content])
        if not content:
            continue
        prompt = f"Analyze the following group chat content and suggest educational project ideas: {content[:1000]}"
        try:
            response = assistant.get_response(prompt)
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                logger.warning(f"No admin user found for group {group.name}")
                continue
            suggestion_message = Message(
                user_id=admin_user.id,
                group_id=group.id,
                content=f"AI Suggestion: {response}",
                message_type='text'
            )
            db.session.add(suggestion_message)
            db.session.commit()
            logger.info(f"Generated suggestion for group {group.name}")
        except Exception as e:
            logger.error(f"Failed to generate suggestion for group {group.id}: {str(e)}")

def check_schema():
    """Check if the user table has the required columns."""
    try:
        conn = db.engine.connect()
        result = conn.execute("PRAGMA table_info(user)")
        columns = [row[1] for row in result.fetchall()]
        required_columns = ['id', 'username', 'password_hash', 'is_admin']
        missing_columns = [col for col in required_columns if col not in columns]
        conn.close()
        if missing_columns:
            logger.error(f"Missing columns in user table: {missing_columns}")
            return False
        return True
    except Exception as e:
        logger.error(f"Failed to check schema: {str(e)}")
        return False

def create_default_admin():
    with app.app_context():
        # if not check_schema():
        #     logger.error("Schema check failed. Ensure migrations are applied.")
        #     raise Exception("Database schema is incorrect. Run 'flask db upgrade' to apply migrations.")
        admin = User.query.filter_by(username='admin').first()
        if not admin or not admin.is_admin:
            password = 'admin123'
            admin = User(username='admin', is_admin=True)
            admin.password = password
            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin user created.")

if __name__ == '__main__':
    # start_chrome()  # Commented out due to missing Chrome
    with app.app_context():
        try:
            db.create_all()
            #logger.info("Database tables created or verified.")
            create_default_admin()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}", exc_info=True)
            raise

    app.run(debug=True, port=5003)