import os
import hashlib
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, ValidationError
from wtforms.validators import DataRequired, EqualTo
from flask_ckeditor import CKEditor


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SECRET_KEY'] = 'yandexlyceum_secret_key_for_project'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
ckeditor = CKEditor(app)


class LoginForm(FlaskForm):

    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):

    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField(
        'Пароль', 
        validators=[
            DataRequired(), 
            EqualTo('password2', message='Пароли не совпадают.')
        ]
    )
    password2 = PasswordField('Подтвердите пароль ещё раз', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

    def validate_login(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Такой пользователь уже существует.')


class PostForm(FlaskForm):
    body = TextAreaField("Есть новая зарубка?", validators=[DataRequired()])
    submit = SubmitField('Отправить')


class EditProfileForm(FlaskForm):
    about = TextAreaField('Обо мне')
    submit = SubmitField('Обновить')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(
        'Старый пароль', 
        validators=[DataRequired()]
    )
    password = PasswordField(
        'Новый пароль', 
        validators=[
            DataRequired(), 
            EqualTo('password2', message='Пароли не совпадают.')
        ]
    )
    password2 = PasswordField(
        'Новый пароль ещё раз', 
        validators=[DataRequired()]
    )
    submit = SubmitField('Сменить')


class User(UserMixin, db.Model):

    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    about = db.Column(db.Text)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    @property
    def password(self):
        raise AttributeError('пароль прочесть нельзя.')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def gravatar(self, size=100, default='identicon', rating='g'):
        url = 'https://secure.gravatar.com/avatar'
        email = '{}@bookmarks.ru'.format(self.username.lower()).encode('utf-8')
        email_hash = hashlib.md5(email).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=email_hash, size=size, default=default, rating=rating)
    
    def robohash(self, size=200):
        url = 'https://robohash.org/'
        return url + self.username + '?set=set2&size={}x{}'.format(size, size)


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@app.context_processor
def inject_app_name():
    return dict(app_name="Зарубки")


@app.route('/', methods=['GET', 'POST'])
def index():
    admin_posts = Post.query.filter_by(author_id=1).order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=admin_posts)


@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    form = PostForm()
    
    if form.validate_on_submit():
        post = Post(body=form.body.data, author_id=current_user.get_id())
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('posts'))

    user_posts = Post.query.filter_by(author_id=current_user.get_id()).order_by(Post.timestamp.desc()).all()
    return render_template('posts.html', form=form, posts=user_posts)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user1 = User.query.filter_by(username=form.login.data).first()
        if user1 is not None and user1.verify_password(form.password.data):
            login_user(user1, False)
            return redirect(url_for('index'))
        flash('Неправильный логин или пароль.')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли.')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user1 = User(username=form.login.data, password=form.password.data)
        db.session.add(user1)
        db.session.commit()
        flash('Теперь вы можете войти.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Post.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('posts'))


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if int(current_user.get_id()) != int(post.author_id):
        abort(403)
        
    form = PostForm()
    
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        db.session.commit()
        flash('Запись успешно изменена.')
        return redirect(url_for('edit_post', post_id=post.id))
    
    form.body.data = post.body
    return render_template('edit_post.html', form=form)


@app.route('/user/<int:user_id>', methods=['GET', 'POST'])
def user(user_id):
    user1 = User.query.filter_by(id=user_id).first_or_404()
    posts_count = Post.query.filter_by(author_id=user_id).count()
    form = EditProfileForm()
    if form.validate_on_submit():
        user1.about = form.about.data
        db.session.commit()
        flash('Ваш профиль обновлён!')
        return redirect(url_for('user', user_id=user_id))
    return render_template('user.html', user=user1, posts_count=posts_count, form=form)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Ваш пароль изменён.')
            return redirect(url_for('user', user_id=current_user.get_id()))
        else:
            flash('Ошибка пароля.')
    return render_template("change_password.html", form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    return render_template('401.html'), 401


if __name__ == "__main__":
    app.run()
