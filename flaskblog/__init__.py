from flask import Flask, request, jsonify, make_response
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
import os
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
from flask_ckeditor import CKEditor

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app,db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

app.config['CKEDITOR_PKG_TYPE'] = 'basic'
ckeditor = CKEditor(app)


import flaskblog.forms as views
admin = Admin(app, index_view=views.MyAdminIndexView())
admin.add_view(views.UserAdminView(views.User, db.session))


from flaskblog import routes
