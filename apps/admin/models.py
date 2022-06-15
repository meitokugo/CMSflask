# encoding:utf-8
from werkzeug.security import generate_password_hash, check_password_hash

from exts import db
from datetime import datetime


class Users(db.Model):
    __tablename__ = 'jq_user'
    uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # gid=db.Column(db.Integer,nullable=True)
    username = db.Column(db.String(50), nullable=False, unique=True)  # 用户名不能为空,而且必须是唯一的
    password = db.Column(db.String(100), nullable=False)  # 密码不能为空
    # _password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)  # 用户邮箱不能为空，而且必须是唯一的

     def __init__(self, username, password, email):
         self.username = username
         self.password = password
         self.email = email

     @property
     def password(self):
         return self._password

     @password.setter
     def password(self, raw_password):
         self._password = generate_password_hash(raw_password)

     def check_password(self, raw_password):
         result = check_password_hash(self.password, raw_password)  #
         return result
