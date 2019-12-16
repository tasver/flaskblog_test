from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import widgets, DateTimeField, StringField, PasswordField, SubmitField, BooleanField,TextAreaField
from wtforms.validators import InputRequired, DataRequired, Length, Email, EqualTo, ValidationError
from flaskblog.models import User
from flask import flash

from flask_ckeditor import CKEditorField

from flask_admin.contrib.sqla import ModelView
from flask_admin import BaseView, expose, AdminIndexView
from flask_admin.form import rules
from flaskblog import bcrypt


class RegistrationForm(FlaskForm):
    username=StringField('Username', validators=[DataRequired(),Length(min=2,max=20)])
    email=StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password',validators = [DataRequired()])
    confirm_password = PasswordField('Confirm Password',validators = [DataRequired(), EqualTo('password')])
    submit= SubmitField('Sign up')
    def validate_field(self,field):
        if True:
            raise ValidationError('Validation message')
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one')
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

class LoginForm(FlaskForm):
    email =StringField('Email', validators = [DataRequired(),Email()])
    password = PasswordField('Password',validators = [DataRequired()])
    remember = BooleanField('Remember Me')
    submit= SubmitField('Log in')

class UpdateAccountForm(FlaskForm):
    username=StringField('Username', validators=[DataRequired(),Length(min=2,max=20)])
    email=StringField('Email', validators=[DataRequired(),Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg','png'])])
    submit= SubmitField('Update')
    about = CKEditorField('About', validators=[DataRequired(),Length(max=500)])
    new_password = PasswordField('New password',validators = [DataRequired()])
    passwordcheck = PasswordField('Old password',validators = [DataRequired()])
    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one')
    def validate_email(self,email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(),Length(min=2,max=20)])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg','png'])])
    follow = SubmitField('Follow')
    unfollow = SubmitField('Unfollow')
    about = TextAreaField('About', validators=[DataRequired(),Length(max=500)])
    lastseen = DateTimeField('Lastseen', format='%Y-%m-%d %H:%M:%S', validators = [DataRequired()])

class AdminUserCreateForm(FlaskForm):
    username = StringField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired()])
    admin = BooleanField('Is Admin ?')
class AdminUserUpdateForm(FlaskForm):
    username = StringField('Username', [InputRequired()])
    admin = BooleanField('Is Admin ?')


class MyAdminIndexView(AdminIndexView):

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin()

class CKTextAreaWidget(widgets.TextArea):
    def __call__(self, field, **kwargs):
        kwargs.setdefault('class_', 'ckeditor')
        return super(CKTextAreaWidget, self).__call__(field, **kwargs)

class CKTextAreaField(TextAreaField):
    widget = CKTextAreaWidget()

class UserAdminView(ModelView):
    column_searchable_list = ('username',)
    column_sortable_list = ('username', 'admin')
    form_overrides = dict(about=CKEditorField)
    create_template = 'edit.html'
    edit_template = 'edit.html'
    #column_exclude_list = ('password',)
    #form_excluded_columns = ('password',)

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin()

    def scaffold_form(self):
        form_class = super(UserAdminView, self).scaffold_form()
        form_class.password = PasswordField('Password')
        form_class.new_password = PasswordField('New Password')
        form_class.confirm = PasswordField('Confirm New Password')
        return form_class

    def create_model(self, form):
        model = self.model(
            form.username.data, form.password.data, form.admin.data
        )
        form.populate_obj(model)
        model.password = bcrypt.generate_password_hash(form.password.data)
        self.session.add(model)
        self._on_model_change(form, model, True)
        self.session.commit()

    form_edit_rules = ('username', 'admin', 'about',rules.Header('Reset Password'),'new_password', 'confirm')
    form_create_rules = ('username', 'admin', 'email', 'about', 'password')

    def update_model(self, form, model):
        form.populate_obj(model)
        if form.new_password.data:
            if form.new_password.data != form.confirm.data:
                return flash('Passwords must match')
            model.password = bcrypt.generate_password_hash(form.new_password.data)
        self.session.add(model)
        self._on_model_change(form, model, False)
        self.session.commit()
