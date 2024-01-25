from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    project = db.Column(db.String(80), nullable=True)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=False)
    short_description = db.Column(db.String(300))
    users = db.Column(db.String(100))
    # description = db.Column(db.String(600))
    # users = db.Column()
