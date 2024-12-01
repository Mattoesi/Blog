from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, session, get_flashed_messages
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from datetime import datetime
from flask_gravatar import Gravatar
import urllib, hashlib
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI")
print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
ckeditor = CKEditor(app)
Bootstrap5(app)
csrf = CSRFProtect(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

def get_gravatar(email, size=200, default_image='identicon'):
    print(f"Email received: {email}")
    md5_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    gravatar_url = f'https://www.gravatar.com/avatar/{md5_hash}?s={size}&d={default_image}'
    print(f"Gravatar URL generated: {gravatar_url}")
    return gravatar_url

# TODO: Configure Flask-Login
# CREATE LOGIN
login_manager = LoginManager(app)

# CREATE USER CALLBACK
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(app)
# db.init_app(app)


with app.app_context():
    db.create_all()


# CONFIGURE TABLES

# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(50), unique=True, nullable=False)
    blogposts = relationship('BlogPost', back_populates='author' )
    comments = relationship('Comment', back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship('User', back_populates='blogposts')
    comments = relationship('Comment', back_populates='parent_post')

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(600), nullable=False)
    posted_time = db.Column(db.DateTime, nullable=False)

    # ***************Child Relationship for User*************#
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comments", foreign_keys=[author_id])

    # ***************Child Relationship for BlogPost*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


def calculate_time_difference(posted_time):
    current_time = datetime.now()
    time_difference = current_time - posted_time

    # Extract days, hours, and minutes
    days = time_difference.days

     # the divmod divide the time_difference.seconds by 3600 and then save the answer as a tuple, with the whole number and remainder,
      # as hours and remainder(minutes) respectively. the same as the second tuple, only that the remainder( _ ) which is the seconds is not needed.
    hours, remainder = divmod(time_difference.seconds, 3600)
    minutes, _ = divmod(remainder, 60)

    if days > 0:
        return f"{days} days ago"
    elif hours > 0:
        return f"{hours} hours ago"
    elif minutes > 0:
        return f"{minutes} minutes ago"
    else:
        return "just now"


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        existing_email = result.scalar()
        if existing_email:
            flash('Email address already in use. Please choose a different one.', 'error')
            return redirect(url_for('login'))
        # Hashing and salting
        hash_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_salted_password,
        )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flashed_messages = get_flashed_messages(with_categories=True, category_filter=['error'])
        for message, category in flashed_messages:
            flash(message, category)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email address does not exist', 'error')
            return redirect(url_for('login'))
        if not check_password_hash(user.password, password):
            flash('Password is incorrect', 'error')
            return redirect(url_for('login'))
        login_user(user)
        flash(f'Login successful! Welcome {current_user.name}.', 'success')
        return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    user_name = current_user.name
    flash(f'Successfully logged out {user_name}.')
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/', methods=["GET", "POST"])
def get_all_posts():
    user_id = request.args.get('user_id')
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    if 'success' in request.args.get('flash_messages', '').lower() and current_user.is_authenticated:
        flash('Login successful!', 'success')
    flashed_messages = get_flashed_messages(with_categories=True, category_filter=['error'])
    for message, category in flashed_messages:
        flash(message, category)

    return render_template("index.html", all_posts=posts, current_user=current_user)



# TODO: Allow logged-in users to comment on posts
@login_required
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    if current_user.is_anonymous:
        flash('You need to login first.')
        return redirect(url_for('login'))
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    existing_comments = Comment.query.filter_by(post_id=post_id).all()
    gravatar_url = get_gravatar(current_user.email)
    if comment_form.validate_on_submit():
        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post,
            posted_time=datetime.now()
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Your comment has been added successfully!', 'error')
        existing_comments = Comment.query.filter_by(post_id=post_id).all()
        gravatar_url = get_gravatar(current_user.email)
    the_time = []
    for comments_time in existing_comments:
        print(comments_time.posted_time)
        time = calculate_time_difference(comments_time.posted_time)
        the_time.append(time)
    flashed_messages = get_flashed_messages(with_categories=True, category_filter=['error'])
    for message, category in flashed_messages:
        flash(message, category)
    print(the_time)
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form, comments=existing_comments, gravatar_url=gravatar_url, get_gravatar=get_gravatar, posted_time=the_time)



def admin_only(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        return func(*args, **kwargs)
    return wrapper


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete-comment/<int:comment_id>/<int:post_id>")
@login_required
def delete_comment(comment_id, post_id):
    post = db.get_or_404(BlogPost, post_id)
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post.id))

@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route('/execute-sql')
def execute_sql():
    try:
        db.session.execute("CREATE TABLE test_table (id SERIAL PRIMARY KEY, name TEXT)")
        db.session.commit()
        return "SQL executed successfully"
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    app.run(debug=False, port=5002)
