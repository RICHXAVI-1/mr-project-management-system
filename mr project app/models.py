from datetime import datetime
import os
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    topic_title = db.Column(db.String(200), nullable=True)
    approval_code = db.Column(db.String(20), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    is_restricted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    documents = db.relationship('Document', backref='user', lazy=True)
    sent_messages = db.relationship('Message', 
                                   foreign_keys='Message.sender_id',
                                   backref='sender', 
                                   lazy='dynamic')
    received_messages = db.relationship('Message', 
                                       foreign_keys='Message.recipient_id',
                                       backref='recipient', 
                                       lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.email}>'


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin_upload = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<Document {self.filename}>'


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    is_group_message = db.Column(db.Boolean, default=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # New column to store voice-note filename/path
    audio_path = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f'<Message {self.id}>'


class ApprovalCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)
    used_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    used_by_user = db.relationship('User', foreign_keys=[used_by])
    
    def __repr__(self):
        return f'<ApprovalCode {self.code}>'


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<OTP {self.code}>'
