"""
https://pythonhosted.org/Flask-Gravatar/
pip install Flask-Gravatar
"""

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, UserRegisterForm, UserLoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import g, request

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)


# Provide a user_loader callback
# This callback is used to reload the user object from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return UserInfo.query.get(user_id)


# avatar
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False,
                    use_ssl=False, base_url=None)


##CONFIGURE TABLES

class BlogPost(db.Model):
    query: db.Query  # # Type hint here, PyCharm SqlAlchemy autocomplete
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, ForeignKey('user_info.id'))
    author = relationship('UserInfo', back_populates="posts")

    comments = relationship('Comment', back_populates="parent_post")


class UserInfo(UserMixin, db.Model):
    query: db.Query  # # Type hint here, PyCharm SqlAlchemy autocomplete
    __tablename__ = "user_info"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    query: db.Query  # # Type hint here, PyCharm SqlAlchemy autocomplete
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, ForeignKey('user_info.id'))
    comment_author = relationship('UserInfo', back_populates="comments")

    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates="comments")


db.create_all()


# admin-only decorator
def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id != 1:
                return abort(403)
            return func(*args, **kwargs)
        else:
            flash("Please log in.")
            return redirect(url_for('login', next=request.url))

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = UserRegisterForm()
    if form.validate_on_submit():
        input_email = form.email.data
        user_obj = UserInfo.query.filter_by(email=input_email).first()
        if user_obj:
            flash("You've already sign up with that email, log in instead.")
            return redirect(url_for('login'))

        hash_pwd = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8,
        )
        new_user = UserInfo(
            name=form.name.data,
            email=input_email,
            password=hash_pwd,
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = UserLoginForm()
    next_url = request.args.get('next')
    if form.validate_on_submit():
        user_obj: UserInfo = UserInfo.query.filter_by(email=form.email.data).first()
        if user_obj and check_password_hash(user_obj.password, form.password.data):
            login_user(user_obj)
            if next_url:
                return redirect(next_url)
            return redirect(url_for('get_all_posts'))
        flash("Email or password incorrect, please try again.")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for('login', next=request.url))
        new_comment = Comment(
            text=form.comment_text.data,
            author_id=current_user.id,
            post_id=post_id,
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template(
        "post.html",
        post=requested_post,
        form=form,
        gravatar=gravatar,
    )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


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
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
