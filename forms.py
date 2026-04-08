
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User, ApprovalCode

# Authentication Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')


class SignupForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[DataRequired(), Length(min=5, max=20)])
    approval_code = StringField('Approval Code', validators=[DataRequired(), Length(min=4, max=20)])
    topic_title = StringField('Project/Thesis Topic', validators=[DataRequired(), Length(min=5, max=200)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please use a different email.')
            
    def validate_approval_code(self, approval_code):
        code = ApprovalCode.query.filter_by(code=approval_code.data).first()
        if not code:
            raise ValidationError('Invalid approval code. Please contact support to get a valid code.')
        if code.is_used:
            raise ValidationError('This approval code has already been used. Please contact support.')


class OTPVerificationForm(FlaskForm):
    otp = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):
    otp = StringField('OTP Code', validators=[DataRequired(), Length(min=6, max=6)])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')


# Client Forms
class ProfileUpdateForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    phone = StringField('Phone Number', validators=[DataRequired(), Length(min=5, max=20)])
    topic_title = StringField('Project/Thesis Topic', validators=[DataRequired(), Length(min=5, max=200)])
    submit = SubmitField('Update Profile')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')


class DocumentUploadForm(FlaskForm):
    file = FileField('Select File', validators=[
        FileRequired(),
        FileAllowed(['doc', 'docx', 'pdf', 'txt', 'xlsx', 'pptx', 'zip'], 'Unsupported file type')
    ])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Upload Document')


class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Send Message')


# Admin Forms
class ApprovalCodeForm(FlaskForm):
    code = StringField('Approval Code', validators=[Length(max=20)], 
                       description='Leave blank to auto-generate')
    submit = SubmitField('Generate Code')


class AdminDocumentUploadForm(FlaskForm):
    client = SelectField('Client', coerce=int, validators=[DataRequired()])
    file = FileField('Select File', validators=[
        FileRequired(),
        FileAllowed(['doc', 'docx', 'pdf', 'txt', 'xlsx', 'pptx', 'zip'], 'Unsupported file type')
    ])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Upload Document')


class AdminMessageForm(FlaskForm):
    recipient = SelectField('Client', coerce=int)
    is_group = BooleanField('Send to all clients')
    content = TextAreaField('Message', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Send Message')


class DeleteForm(FlaskForm):
    submit = SubmitField('Delete')
