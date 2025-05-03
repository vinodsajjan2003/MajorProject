from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, URL, ValidationError, Optional
from models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one or login.')

class URLScanForm(FlaskForm):
    url = StringField('Dark Web URL', validators=[DataRequired()])
    submit = SubmitField('Scan URL')

class AutoScanURLForm(FlaskForm):
    url = StringField('URL to Monitor', validators=[DataRequired()])
    description = TextAreaField('Description (optional)', validators=[Optional()])
    
    # Notification settings
    email_notification = BooleanField('Email Notification', default=True)
    notification_email = StringField('Notification Email', validators=[Optional(), Email()])
    
    # Schedule settings
    scan_frequency = SelectField('Scan Frequency', 
                               choices=[('daily', 'Daily'), 
                                        ('weekly', 'Weekly'), 
                                        ('monthly', 'Monthly')],
                               default='daily')
    
    submit = SubmitField('Save Auto-Scan URL')
