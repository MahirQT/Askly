import os
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from openai import OpenAI
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv
from sqlalchemy import func

load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key-for-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['OPENAI_API_KEY'] = os.getenv('OPENAI_API_KEY')  # From .env file

# Initialize extensions
db = SQLAlchemy(app)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Create upload folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='student')  # 'student', 'teacher' or 'senior'
    points = db.Column(db.Integer, default=0)
    doubts_posted = db.Column(db.Integer, default=0)
    doubts = db.relationship('Doubt', backref='author', lazy=True)
    solutions = db.relationship('Solution', backref='solver', lazy=True)
    votes = db.relationship('Vote', backref='voter', lazy=True)
    comments = db.relationship('Comment', backref='commenter', lazy=True)

    def __init__(self, name, email, password, role='student'):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.role = role
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class Doubt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(50), nullable=False)  # Added subject field
    image_path = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    solved = db.Column(db.Boolean, default=False)
    solutions = db.relationship('Solution', backref='doubt', lazy=True)
    comments = db.relationship('Comment', backref='doubt', lazy=True)

class Solution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(300))
    solved_by = db.Column(db.String(100), nullable=False)
    solver_role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    doubt_id = db.Column(db.Integer, db.ForeignKey('doubt.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    votes = db.relationship('Vote', backref='solution', lazy=True)

    @property
    def upvotes(self):
        return Vote.query.filter_by(solution_id=self.id, is_upvote=True).count()

    @property
    def downvotes(self):
        return Vote.query.filter_by(solution_id=self.id, is_upvote=False).count()

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_upvote = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    solution_id = db.Column(db.Integer, db.ForeignKey('solution.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doubt_id = db.Column(db.Integer, db.ForeignKey('doubt.id'), nullable=False)

class Redemption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=False)
    points = db.Column(db.Integer, nullable=False)
    redeemed_at = db.Column(db.DateTime, default=datetime.utcnow)

# friendrequest model
class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_requests')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_requests')

#Chat Message Model
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])


#Notification Model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50))  # 'solution', 'comment', 'friend_request'
    reference_id = db.Column(db.Integer)  # ID of related doubt/comment/etc
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='notifications')


# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash('Please login to view this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'email' not in session:
                flash('Please login to view this page', 'error')
                return redirect(url_for('login'))
            user = User.query.filter_by(email=session['email']).first()
            if user.role not in roles:
                flash('You do not have permission to view this page', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))

        new_user = User(name=name, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            session['name'] = user.name
            session['user_id'] = user.id
            session['role'] = user.role
            
            if user.role in ['teacher', 'senior']:
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Student Routes
@app.route('/dashboard')
@login_required
def dashboard():
    if session['role'] in ['teacher', 'senior']:
        return redirect(url_for('teacher_dashboard'))
    
    user = User.query.get(session['user_id'])
    
    # Get all subjects with doubts count
    subjects = db.session.query(
        Doubt.subject,
        func.count(Doubt.id).label('doubt_count')
    ).filter_by(user_id=user.id).group_by(Doubt.subject).all()
    
    # Get doubts grouped by subject
    doubts_by_subject = {}
    for subject, _ in subjects:
        doubts = Doubt.query.filter_by(
            user_id=user.id,
            subject=subject
        ).order_by(Doubt.created_at.desc()).all()
        doubts_by_subject[subject] = doubts
    
    # Get solved doubts grouped by subject
    solved_by_subject = {}
    solved_doubts = Doubt.query.filter_by(
        user_id=user.id,
        solved=True
    ).all()
    
    for doubt in solved_doubts:
        if doubt.subject not in solved_by_subject:
            solved_by_subject[doubt.subject] = []
        solved_by_subject[doubt.subject].append(doubt)
    
    # Get ranking data
    top_students = User.query.filter_by(role='student').order_by(User.doubts_posted.desc()).limit(5).all()
    top_teachers = User.query.filter(User.role.in_(['teacher', 'senior'])).order_by(User.points.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         name=user.name,
                         subjects=subjects,
                         doubts_by_subject=doubts_by_subject,
                         solved_by_subject=solved_by_subject,
                         top_students=top_students,
                         top_teachers=top_teachers)

@app.route('/ask', methods=['GET', 'POST'])
@login_required
def ask_doubt():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        subject = request.form['subject']
        image = request.files.get('image')
        
        image_path = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = filename
        
        user = User.query.get(session['user_id'])
        new_doubt = Doubt(
            title=title,
            description=description,
            subject=subject,
            image_path=image_path,
            user_id=user.id
        )
        
        user.doubts_posted += 1
        db.session.add(new_doubt)
        db.session.commit()
        
        flash('Your doubt has been posted!', 'success')
        return redirect(url_for('dashboard'))
    
    # List of available subjects
    subjects = ['Algebra','Calculas','Physics', 'Chemistry', 'Biology','EDS','FOC',
               'English', 'Electronics', 'Critical Thinking','EEE','Others']
    
    return render_template('ask_doubt.html', subjects=subjects)

@app.route('/doubt/<int:doubt_id>')
@login_required
def doubt_detail(doubt_id):
    doubt = Doubt.query.get_or_404(doubt_id)
    return render_template('doubt_detail.html', doubt=doubt)

@app.route('/vote/<int:solution_id>/<vote_type>')
@login_required
def vote(solution_id, vote_type):
    solution = Solution.query.get_or_404(solution_id)
    existing_vote = Vote.query.filter_by(user_id=session['user_id'], solution_id=solution_id).first()
    
    if existing_vote:
        if existing_vote.is_upvote and vote_type == 'up':
            # Remove upvote and deduct points
            teacher = User.query.get(solution.user_id)
            teacher.points = max(0, teacher.points - 10)
            db.session.delete(existing_vote)
        elif not existing_vote.is_upvote and vote_type == 'down':
            # Remove downvote
            db.session.delete(existing_vote)
        else:
            # Change vote type
            if vote_type == 'up':
                teacher = User.query.get(solution.user_id)
                teacher.points += 10
            existing_vote.is_upvote = (vote_type == 'up')
    else:
        if vote_type == 'up':
            teacher = User.query.get(solution.user_id)
            teacher.points += 10
        new_vote = Vote(
            is_upvote=(vote_type == 'up'),
            user_id=session['user_id'],
            solution_id=solution_id
        )
        db.session.add(new_vote)
    
    db.session.commit()
    return redirect(url_for('doubt_detail', doubt_id=solution.doubt_id))

@app.route('/comment/<int:doubt_id>', methods=['POST'])
@login_required
def add_comment(doubt_id):
    text = request.form.get('comment_text')
    if not text:
        flash('Comment cannot be empty', 'error')
        return redirect(url_for('doubt_detail', doubt_id=doubt_id))
    
    new_comment = Comment(
        text=text,
        user_id=session['user_id'],
        doubt_id=doubt_id
    )
    db.session.add(new_comment)
    db.session.commit()
    
    return redirect(url_for('doubt_detail', doubt_id=doubt_id))

# Teacher Routes
@app.route('/teacher_dashboard')
@role_required(['teacher', 'senior'])
def teacher_dashboard():
    teacher = User.query.get(session['user_id'])
    
    # Get filter parameters
    subject_filter = request.args.get('subject', '')
    search_query = request.args.get('search', '')
    
    # Base query for unsolved doubts
    query = Doubt.query.filter_by(solved=False)
    
    # Apply filters
    if subject_filter:
        query = query.filter_by(subject=subject_filter)
    if search_query:
        query = query.filter(Doubt.title.contains(search_query) | 
               Doubt.description.contains(search_query))
    
    # Get filtered doubts
    unsolved_doubts = query.order_by(Doubt.created_at.desc()).all()
    
    # Get all distinct subjects for filter dropdown
    subjects = db.session.query(Doubt.subject).distinct().all()
    subjects = [s[0] for s in subjects]
    
    # Get recent comments
    teacher_solution_ids = [s.id for s in teacher.solutions]
    recent_comments = Comment.query.join(Doubt).filter(
        Doubt.solutions.any(Solution.id.in_(teacher_solution_ids))
    ).order_by(Comment.created_at.desc()).limit(5).all()
    
    # Get ranking data
    top_students = User.query.filter_by(role='student').order_by(User.doubts_posted.desc()).limit(5).all()
    top_teachers = User.query.filter(User.role.in_(['teacher', 'senior'])).order_by(User.points.desc()).limit(5).all()
    
    return render_template('teacher_dashboard.html',
                         unsolved_doubts=unsolved_doubts,
                         subjects=subjects,
                         current_subject=subject_filter,
                         search_query=search_query,
                         teacher=teacher,
                         recent_comments=recent_comments,
                         top_students=top_students,
                         top_teachers=top_teachers)

@app.route('/solve/<int:doubt_id>', methods=['GET', 'POST'])
@role_required(['teacher', 'senior'])
def solve_doubt(doubt_id):
    doubt = Doubt.query.get_or_404(doubt_id)
    teacher = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        solution_text = request.form['solution']
        solution_image = request.files.get('solution_image')
        
        image_path = None
        if solution_image and allowed_file(solution_image.filename):
            filename = secure_filename(solution_image.filename)
            solution_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = filename
        
        solution = Solution(
            text=solution_text,
            image_path=image_path,
            solved_by=teacher.name,
            solver_role=teacher.role,
            doubt_id=doubt.id,
            user_id=teacher.id
        )
        
        doubt.solved = True
        db.session.add(solution)
        db.session.commit()
        
        flash('Solution submitted successfully!', 'success')
        return redirect(url_for('teacher_dashboard'))
    
    return render_template('solve_doubt.html', doubt=doubt)

@app.route('/redeem', methods=['GET', 'POST'])
@role_required(['teacher', 'senior'])
def redeem_points():
    teacher = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        points_to_redeem = min(teacher.points, int(request.form['points']))
        if points_to_redeem >= 100:  # Minimum redemption threshold
            # Generate unique redemption code
            redemption_code = f"VOUCHER-{datetime.now().strftime('%Y%m%d')}-{teacher.id}-{secrets.token_hex(4).upper()}"
            
            # Create redemption record
            redemption = Redemption(
                user_id=teacher.id,
                code=redemption_code,
                points=points_to_redeem
            )
            
            # Update teacher points
            teacher.points -= points_to_redeem
            
            db.session.add(redemption)
            db.session.commit()
            
            flash(f'Success! Your voucher code: {redemption_code}', 'success')
            return redirect(url_for('teacher_dashboard'))
        else:
            flash('You need at least 100 points to redeem', 'error')
    
    return render_template('redeem.html', teacher=teacher)

# Doubt Library Route
@app.route('/doubt_library')
@login_required
def doubt_library():
    # Get filter parameters
    subject_filter = request.args.get('subject', '')
    search_query = request.args.get('search', '')
    
    # Base query for solved doubts
    query = Doubt.query.filter_by(solved=True)
    
    # Apply filters
    if subject_filter:
        query = query.filter_by(subject=subject_filter)
    if search_query:
        query = query.filter(Doubt.title.contains(search_query) | 
                           Doubt.description.contains(search_query))
    
    # Get all solved doubts
    solved_doubts = query.order_by(Doubt.created_at.desc()).all()
    
    # Get all distinct subjects for filter dropdown
    subjects = db.session.query(Doubt.subject).distinct().all()
    subjects = [s[0] for s in subjects]
    
    return render_template('doubt_library.html',
                         solved_doubts=solved_doubts,
                         subjects=subjects,
                         current_subject=subject_filter,
                         search_query=search_query)

# Student Community Routes
@app.route('/student_community')
@login_required
def student_community():
    current_user = User.query.get(session['user_id'])
    # Get all students except current user
    students = User.query.filter(User.role == 'student', User.id != current_user.id).all()
    
    # Get friend requests
    received_requests = FriendRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()
    sent_requests = FriendRequest.query.filter_by(sender_id=current_user.id).all()
    
    # Get friends (accepted requests)
    friends = []
    accepted_sent = FriendRequest.query.filter_by(sender_id=current_user.id, status='accepted').all()
    accepted_received = FriendRequest.query.filter_by(receiver_id=current_user.id, status='accepted').all()
    
    for req in accepted_sent:
        friends.append(req.receiver)
    for req in accepted_received:
        friends.append(req.sender)
    
    return render_template('student_community.html',
                         students=students,
                         received_requests=received_requests,
                         sent_requests=sent_requests,
                         friends=friends)

@app.route('/send_request/<int:receiver_id>', methods=['POST'])
@login_required
def send_request(receiver_id):
    sender_id = session['user_id']
    
    # Check if request already exists
    existing = FriendRequest.query.filter_by(sender_id=sender_id, receiver_id=receiver_id).first()
    if existing:
        flash('Request already sent', 'info')
        return redirect(url_for('student_community'))
    
    # Create new request
    request = FriendRequest(sender_id=sender_id, receiver_id=receiver_id)
    db.session.add(request)
    
    # Create notification
    sender = User.query.get(sender_id)
    notification = Notification(
        user_id=receiver_id,
        content=f"{sender.name} sent you a friend request",
        notification_type='friend_request',
        reference_id=request.id
    )
    db.session.add(notification)
    
    db.session.commit()
    flash('Friend request sent', 'success')
    return redirect(url_for('student_community'))

@app.route('/respond_request/<int:request_id>/<action>')
@login_required
def respond_request(request_id, action):
    request = FriendRequest.query.get_or_404(request_id)
    
    if request.receiver_id != session['user_id']:
        flash('Unauthorized', 'error')
        return redirect(url_for('student_community'))
    
    if action == 'accept':
        request.status = 'accepted'
        # Create notification for sender
        receiver = User.query.get(session['user_id'])
        notification = Notification(
            user_id=request.sender_id,
            content=f"{receiver.name} accepted your friend request",
            notification_type='friend_request',
            reference_id=request.id
        )
        db.session.add(notification)
        flash('Request accepted', 'success')
    else:
        request.status = 'rejected'
        flash('Request rejected', 'info')
    
    db.session.commit()
    return redirect(url_for('student_community'))

@app.route('/chat/<int:friend_id>')
@login_required
def chat(friend_id):
    # Verify friendship
    friendship1 = FriendRequest.query.filter_by(
        sender_id=session['user_id'],
        receiver_id=friend_id,
        status='accepted'
    ).first()
    
    friendship2 = FriendRequest.query.filter_by(
        sender_id=friend_id,
        receiver_id=session['user_id'],
        status='accepted'
    ).first()
    
    if not friendship1 and not friendship2:
        flash('You can only chat with friends', 'error')
        return redirect(url_for('student_community'))
    
    friend = User.query.get_or_404(friend_id)
    messages = ChatMessage.query.filter(
        ((ChatMessage.sender_id == session['user_id']) & (ChatMessage.receiver_id == friend_id)) |
        ((ChatMessage.sender_id == friend_id) & (ChatMessage.receiver_id == session['user_id']))
    ).order_by(ChatMessage.created_at).all()
    
    return render_template('chat.html', friend=friend, messages=messages)

@app.route('/send_message/<int:receiver_id>', methods=['POST'])
@login_required
def send_message(receiver_id):
    message = request.form.get('message')
    if not message:
        flash('Message cannot be empty', 'error')
        return redirect(url_for('chat', friend_id=receiver_id))
    
    new_message = ChatMessage(
        sender_id=session['user_id'],
        receiver_id=receiver_id,
        message=message
    )
    db.session.add(new_message)
    
    # Create notification
    sender = User.query.get(session['user_id'])
    notification = Notification(
        user_id=receiver_id,
        content=f"New message from {sender.name}",
        notification_type='message',
        reference_id=new_message.id
    )
    db.session.add(notification)
    
    db.session.commit()
    return redirect(url_for('chat', friend_id=receiver_id))

# Notification Routes
@app.route('/notifications')
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(
        user_id=session['user_id']
    ).order_by(Notification.created_at.desc()).all()
    
    # Mark as read when viewed
    for notification in user_notifications:
        if not notification.read:
            notification.read = True
    db.session.commit()
    
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/clear_notification/<int:notification_id>')
@login_required
def clear_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != session['user_id']:
        flash('Unauthorized', 'error')
        return redirect(url_for('notifications'))
    
    db.session.delete(notification)
    db.session.commit()
    return redirect(url_for('notifications'))

# Add these to existing routes
def create_solution_notification(doubt, solution):
    notification = Notification(
        user_id=doubt.user_id,
        content=f"Your doubt '{doubt.title}' has been solved by {solution.solved_by}",
        notification_type='solution',
        reference_id=doubt.id
    )
    db.session.add(notification)

def create_comment_notification(doubt, comment):
    # Notify doubt author and other commenters
    users_to_notify = {doubt.user_id}
    
    # Get other users who commented
    other_commenters = {c.user_id for c in doubt.comments if c.user_id != comment.user_id}
    users_to_notify.update(other_commenters)
    
    for user_id in users_to_notify:
        if user_id != comment.user_id:  # Don't notify yourself
            notification = Notification(
                user_id=user_id,
                content=f"New comment on your doubt '{doubt.title}'",
                notification_type='comment',
                reference_id=doubt.id
            )
            db.session.add(notification)

# Dobby AI Assistant
@app.route('/dobby')
@login_required
def dobby():
    return render_template('dobby.html')

@app.route('/ask_dobby', methods=['POST'])
@login_required
def ask_dobby():
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are Dobby..."},
                {"role": "user", "content": request.json.get('message')}
            ],
            temperature=0.7,
            max_tokens=500
        )
        return jsonify({
            'response': response.choices[0].message.content,
            'status': 'success'
        })
    except Exception as e:
        return jsonify({'response': str(e), 'status': 'error'}), 500
    
@app.route('/test_openai')
def test_openai():
    try:
        test = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Say 'test successful'"}]
        )
        return f"Success! Response: {test.choices[0].message.content}"
    except Exception as e:
        return f"Failed: {str(e)}"

# Initialize database
with app.app_context():
    db.create_all()
    # Add default subjects if none exist
    if not Doubt.query.first():
        default_subjects = ['Mathematics', 'Physics', 'Chemistry', 'Biology', 'Computer Science',
                          'English', 'History', 'Geography', 'Economics', 'Business Studies']
        # No need to add subjects directly as they'll be added via the form

if __name__ == '__main__':
    app.run(debug=True, port=5000)