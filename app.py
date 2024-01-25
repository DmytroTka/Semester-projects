from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, EmailField
from wtforms.validators import DataRequired, Email, length
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'key'
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class RegisterForm(FlaskForm):
    username = StringField("Ім'я користувача", validators=[DataRequired(), length(min=3, max=20)])
    email = EmailField("Email", validators=[Email(), DataRequired()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Зареєструватись")


class LoginForm(FlaskForm):
    username = StringField("Ім'я користувача", validators=[DataRequired(), length(min=3, max=20)])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Увійти")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def index():
    projects = Project.query.all()
    print(projects[1].name)
    return render_template('index.html', username=get_username(), projects=projects)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=True)

            return redirect(url_for('index'))
    return render_template('login.html', form=form, username=get_username())


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password, email=email)

        db.session.add(new_user)
        db.session.commit()
        user = User.query.filter_by(username=form.username.data).first()
        login_user(new_user, remember=True)
        return redirect(url_for('index'))
    return render_template('registration.html', form=form, username=get_username())


@app.route('/project_information/<int:project_id>', methods=['GET', 'POST'])
def project_information(project_id):
    if current_user.is_authenticated:
        user_project = current_user.project
    else:
        user_project = None

    choosed_project = Project.query.get(project_id)
    print(choosed_project.name)
    if request.method == 'POST':
        if current_user.is_authenticated:
            print('button was clicked')
            user = User.query.filter_by(username=current_user.username).first()
            project = Project.query.filter_by(id=project_id).first()
            if user.project is None:
                user.project = choosed_project.name
                if project.users is None:
                    project.users = f'{user.username}'
                else:
                    project.users = f'{project.users},{user.username}'
                db.session.commit()
                return redirect(f'/project_information/{project_id}')
            else:
                flash('Ви вже приймаєте участь у іншому проекті.')
        else:
            flash('Для обрання проекту необхідно зареєструватися чи увійти до аккаунту.')
    return render_template('project_information.html', choosed_project=choosed_project,
                           user_project=user_project, username=get_username())


@app.route('/project_information/<int:project_id>/leave', methods=['GET', 'POST'])
def leave_project(project_id):
    if current_user.is_authenticated:
        user = User.query.filter_by(username=current_user.username).first()
        user.project = None
        project = Project.query.filter_by(id=project_id).first()
        project_users = project.users.split(',')
        print(project_users)
        project_users.remove(user.username)
        if len(project_users) != 0:
            project.users = ",".join([str(x) for x in project_users])
        else:
            project.users = None
        db.session.commit()

    return redirect(f'/project_information/{project_id}')


def get_username():
    if current_user.is_authenticated:
        username = current_user.username
    else:
        username = 'Гость'
    return username


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
