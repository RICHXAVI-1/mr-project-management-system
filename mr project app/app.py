import os
import logging
from datetime import datetime, timedelta
import random
import string
import secrets
from flask import Flask, render_template, flash, redirect, url_for, request, abort, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from sqlalchemy.orm import DeclarativeBase
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import validate_csrf, ValidationError


from flask import current_app, send_from_directory, jsonify




# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your-super-secret-key-here-make-it-long-and-random'
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the SQLAlchemy database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL") or "sqlite:///mrproject.db" # Added fallback to sqlite if env var is not set.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configure upload folder for voice notes
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure upload folder for documents
app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload size

# Configure Flask-Mail
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "mrprojectwriting@gmail.com"
app.config["MAIL_PASSWORD"] = "nbtx zpve vdqd lsbc"
app.config["MAIL_DEFAULT_SENDER"] = "info@mrproject.com"

# Ensure upload directory exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Define the Base class for SQLAlchemy
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with the base class
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Mail
mail = Mail(app)

# Import models and forms after initializing extensions to avoid circular imports
with app.app_context():
    from models import User, Document, Message, ApprovalCode, OTP
    from forms import (
        LoginForm, SignupForm, OTPVerificationForm, ProfileUpdateForm,
        ChangePasswordForm, DocumentUploadForm, MessageForm, ApprovalCodeForm,
        AdminDocumentUploadForm, AdminMessageForm, DeleteForm, ForgotPasswordForm,
        ResetPasswordForm
    )
    from utils import send_otp_email, generate_approval_code, send_message_notification

    # Create database tables if they don't exist
    db.create_all()

    # Create admin user if it doesn't exist
    admin_email = "mrprojectwriting@gmail.com"
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(
            name="Admin",
            email=admin_email,
            phone="12345678901",
            is_admin=True,
            is_active=True,
            topic_title="Admin Account"
        )
        admin.set_password("adminpassword")
        db.session.add(admin)
        db.session.commit()
        logging.info("Admin user created")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route("/")
def firstpage():
    return render_template("firstpage.html")


@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/restricted")
@login_required
def restricted():
    if not current_user.is_restricted:
        if current_user.is_admin:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("client_dashboard"))
    return render_template("restricted.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin_dashboard"))
        elif current_user.is_restricted:
            return redirect(url_for("restricted"))
        return redirect(url_for("client_dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if user.is_admin:
                login_user(user, remember=form.remember_me.data)
                flash("Admin login successful.", "success")
                return redirect(url_for("admin_dashboard"))

            # Check if account is restricted
            if user.is_restricted:
                flash("Your account has been restricted. Please contact mrprojectwriting@gmail.com for assistance.", "danger")
                return render_template("login.html", form=form)

            # Generate and store OTP for regular users
            otp_code = ''.join(random.choices(string.digits, k=6))
            expires_at = datetime.utcnow() + timedelta(minutes=10)

            otp = OTP(
                code=otp_code,
                email=user.email,
                expires_at=expires_at
            )
            db.session.add(otp)
            db.session.commit()

            # Send OTP via email
            send_otp_email(user.email, otp_code, user.name)

            # Redirect to OTP verification page
            return redirect(url_for("verify", email=user.email))

        flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    # Get email from GET args or POST form data
    email = request.args.get("email") or request.form.get("email")
    if not email:
        flash("Email not provided.", "danger")
        return redirect(url_for("login"))

    form = OTPVerificationForm()
    if form.validate_on_submit():
        otp = OTP.query.filter_by(
            email=email,
            code=form.otp.data,
            is_used=False
        ).order_by(OTP.created_at.desc()).first()

        if otp and otp.expires_at > datetime.utcnow():
            user = User.query.filter_by(email=email).first()
            if user:
                otp.is_used = True
                db.session.commit()

                login_user(user)
                flash("Login successful.", "success")
                return redirect(url_for("client_dashboard"))
        else:
            flash("Invalid or expired verification code.", "danger")

    return render_template("verify.html", form=form, email=email)


@app.route("/resend_otp")
def resend_otp():
    email = request.args.get("email")
    if not email:
        flash("Email not provided.", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    # Generate and store OTP
    otp_code = ''.join(random.choices(string.digits, k=6))
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    otp = OTP(
        code=otp_code,
        email=user.email,
        expires_at=expires_at
    )
    db.session.add(otp)
    db.session.commit()

    # Send OTP via email
    send_otp_email(user.email, otp_code, user.name)

    flash("A new verification code has been sent to your email.", "success")
    return redirect(url_for("verify", email=email))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = SignupForm()
    if form.validate_on_submit():
        # Verify approval code
        approval_code = ApprovalCode.query.filter_by(code=form.approval_code.data).first()
        if not approval_code or approval_code.is_used:
            flash("Invalid or already used approval code.", "danger")
            return redirect(url_for("signup"))

        # Create new user
        user = User(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            topic_title=form.topic_title.data,
            approval_code=form.approval_code.data,
            is_active=True
        )
        user.set_password(form.password.data)

        # Mark approval code as used
        approval_code.is_used = True
        approval_code.used_by = user.id

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, is_admin=False).first()
        if user:
            otp = ''.join(random.choices(string.digits, k=6))
            expires_at = datetime.utcnow() + timedelta(minutes=10)

            reset_otp = OTP(
                code=otp,
                email=user.email,
                expires_at=expires_at
            )
            db.session.add(reset_otp)
            db.session.commit()

            try:
                send_otp_email(user.email, otp, user.name)
                flash("Password reset instructions sent to your email.", "success")
                return redirect(url_for("reset_password", email=user.email))
            except:
                flash("Error sending email. Please try again.", "danger")
        else:
            flash("Email not found or invalid account type.", "danger")

    return render_template("forgot_password.html", form=form)

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    email = request.args.get("email")
    if not email:
        return redirect(url_for("forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        otp = OTP.query.filter_by(
            email=email,
            code=form.otp.data,
            is_used=False
        ).order_by(OTP.created_at.desc()).first()

        if otp and otp.expires_at > datetime.utcnow():
            user = User.query.filter_by(email=email).first()
            if user:
                user.set_password(form.new_password.data)
                otp.is_used = True
                db.session.commit()
                flash("Password reset successful. Please login.", "success")
                return redirect(url_for("login"))
        else:
            flash("Invalid or expired verification code.", "danger")

    return render_template("reset_password.html", form=form, email=email)


# Client Routes
@app.route("/client/dashboard")
@login_required
def client_dashboard():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    # Get document counts
    document_count = Document.query.filter_by(user_id=current_user.id).count()

    # Get unread messages count
    unread_messages = Message.query.filter_by(
        recipient_id=current_user.id,
        is_read=False
    ).count()

    # Get recent documents (limited to 5)
    recent_documents = Document.query.filter_by(
        user_id=current_user.id
    ).order_by(Document.uploaded_at.desc()).limit(5).all()

    # Get recent messages (limited to 5)
    recent_messages = Message.query.filter_by(
        recipient_id=current_user.id
    ).order_by(Message.created_at.desc()).limit(5).all()

    # Mark messages as read
    for message in recent_messages:
        if not message.is_read:
            message.is_read = True

    db.session.commit()

    return render_template(
        "client/dashboard.html",
        document_count=document_count,
        unread_messages=unread_messages,
        recent_documents=recent_documents,
        recent_messages=recent_messages
    )


@app.route("/client/profile", methods=["GET", "POST"])
@login_required
def client_profile():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    form = ProfileUpdateForm()
    password_form = ChangePasswordForm()

    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.phone = form.phone.data
        current_user.topic_title = form.topic_title.data
        db.session.commit()

        flash("Profile updated successfully.", "success")
        return redirect(url_for("client_profile"))

    # Pre-populate form fields
    if request.method == "GET":
        form.name.data = current_user.name
        form.phone.data = current_user.phone
        form.topic_title.data = current_user.topic_title

    return render_template(
        "client/profile.html",
        form=form,
        password_form=password_form
    )


@app.route("/client/change_password", methods=["POST"])
@login_required
def client_change_password():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    form = ProfileUpdateForm()
    password_form = ChangePasswordForm()

    if password_form.validate_on_submit():
        if current_user.check_password(password_form.current_password.data):
            current_user.set_password(password_form.new_password.data)
            db.session.commit()
            flash("Password changed successfully.", "success")
        else:
            flash("Current password is incorrect.", "danger")

    return redirect(url_for("client_profile"))


@app.route("/client/documents", methods=["GET", "POST"])
@login_required
def client_documents():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    form = DocumentUploadForm()

    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)

        # Generate unique filename to avoid collisions
        unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)

        # Save the file
        file.save(filepath)

        # Create document record
        document = Document(
            filename=filename,
            filepath=filepath,
            description=form.description.data,
            is_admin_upload=False,
            user_id=current_user.id
        )

        db.session.add(document)
        db.session.commit()

        flash("Document uploaded successfully.", "success")
        return redirect(url_for("client_documents"))

    # Get client and admin uploaded documents
    my_documents = Document.query.filter_by(
        user_id=current_user.id,
        is_admin_upload=False
    ).order_by(Document.uploaded_at.desc()).all()

    admin_documents = Document.query.filter_by(
        user_id=current_user.id,
        is_admin_upload=True
    ).order_by(Document.uploaded_at.desc()).all()

    return render_template(
        "client/documents.html",
        form=form,
        my_documents=my_documents,
        admin_documents=admin_documents
    )


@app.route("/client/messages", methods=["GET", "POST"])
@login_required
def client_messages():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    form = MessageForm()

    if form.validate_on_submit():
        # Find admin users
        admin_users = User.query.filter_by(is_admin=True).all()

        if admin_users:
            # Create message to first admin (can be improved to message all or specific admins)
            message = Message(
                content=form.content.data,
                sender_id=current_user.id,
                recipient_id=admin_users[0].id
            )

            db.session.add(message)
            db.session.commit()

            # Send notification email to admin
            try:
                send_message_notification(
                    admin_users[0].email,
                    f"New message from {current_user.name}",
                    f"{current_user.name} sent a new message. Please log in to view it."
                )
            except Exception as e:
                logging.error(f"Failed to send email notification: {e}")

            flash("Message sent successfully.", "success")
        else:
            flash("No admin users found to message.", "danger")

        return redirect(url_for("client_messages"))

    # Get all messages between client and all admins
    admin_ids = [user.id for user in User.query.filter_by(is_admin=True).all()]

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & Message.recipient_id.in_(admin_ids)) |
        ((Message.recipient_id == current_user.id) & Message.sender_id.in_(admin_ids))
    ).order_by(Message.created_at).all()

    # Mark unread messages as read
    unread_messages = Message.query.filter_by(
        recipient_id=current_user.id,
        is_read=False
    ).all()

    for message in unread_messages:
        message.is_read = True

    db.session.commit()

    return render_template(
        "client/messages.html",
        form=form,
        messages=messages
    )


@app.route("/download/<int:document_id>")
@login_required
def download_document(document_id):
    document = Document.query.get_or_404(document_id)

    # Check if user has permission to download this document
    if not current_user.is_admin and document.user_id != current_user.id:
        abort(403)

    if not os.path.exists(document.filepath):
        flash("Document file not found on server.", "danger")
        return redirect(request.referrer or url_for("client_dashboard"))

    return send_file(
        document.filepath,
        download_name=document.filename,
        as_attachment=True
    )


# Admin Routes
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("client_dashboard"))

    # Get counts for dashboard
    client_count = User.query.filter_by(is_admin=False).count()
    document_count = Document.query.count()
    unread_messages = Message.query.filter_by(
        recipient_id=current_user.id,
        is_read=False
    ).count()

    # Get recent clients and documents
    recent_clients = User.query.filter_by(
        is_admin=False
    ).order_by(User.created_at.desc()).limit(5).all()

    recent_documents = Document.query.order_by(
        Document.uploaded_at.desc()
    ).limit(5).all()

    return render_template(
        "admin/dashboard.html",
        client_count=client_count,
        document_count=document_count,
        unread_messages=unread_messages,
        recent_clients=recent_clients,
        recent_documents=recent_documents
    )


@app.route("/admin/clients", methods=["GET", "POST"])
@login_required
def admin_clients():
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("client_dashboard"))

    form = ApprovalCodeForm()

    if form.validate_on_submit():
        code_value = form.code.data.strip() if form.code.data else generate_approval_code()

        # Check if code already exists
        existing_code = ApprovalCode.query.filter_by(code=code_value).first()
        if existing_code:
            flash("This approval code already exists.", "danger")
            return redirect(url_for("admin_clients"))

        new_code = ApprovalCode(code=code_value)
        db.session.add(new_code)
        db.session.commit()

        flash(f"Approval code '{code_value}' generated successfully.", "success")
        return redirect(url_for("admin_clients"))

    # Get clients and approval codes
    clients = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    approval_codes = ApprovalCode.query.order_by(ApprovalCode.created_at.desc()).all()

    return render_template(
        "admin/clients.html",
        form=form,
        clients=clients,
        approval_codes=approval_codes
    )


@app.route("/admin/view_client/<int:client_id>")
@login_required
def admin_view_client(client_id):
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("client_dashboard"))

    client = User.query.filter_by(id=client_id, is_admin=False).first_or_404()

    # Get client documents
    documents = Document.query.filter_by(user_id=client.id).order_by(Document.uploaded_at.desc()).all()

    # Get message history with this client
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == client.id)) |
        ((Message.sender_id == client.id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.created_at).all()

    # Mark unread messages as read
    unread_messages = Message.query.filter_by(
        recipient_id=current_user.id,
        sender_id=client.id,
        is_read=False
    ).all()

    for message in unread_messages:
        message.is_read = True

    db.session.commit()

    # Create forms
    message_form = MessageForm()
    delete_form = DeleteForm()

    return render_template(
        "admin/client_detail.html",
        client=client,
        documents=documents,
        messages=messages,
        message_form=message_form,
        delete_form=delete_form
    )


@app.route("/admin/send_message/<int:client_id>", methods=["POST"])
@login_required
def admin_send_message(client_id):
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("client_dashboard"))

    form = MessageForm()

    if form.validate_on_submit():
        client = User.query.get_or_404(client_id)

        message = Message(
            content=form.content.data,
            sender_id=current_user.id,
            recipient_id=client.id
        )

        db.session.add(message)
        db.session.commit()

        # Send notification email to client
        try:
            send_message_notification(
                client.email,
                "New message from MR PROJECT",
                "You have a new message from our team. Please log in to view it."
            )
        except Exception as e:
            logging.error(f"Failed to send email notification: {e}")

        flash("Message sent successfully.", "success")

    return redirect(url_for("admin_view_client", client_id=client_id))


@app.route("/admin/toggle_restriction/<int:client_id>", methods=["POST"])
@login_required
def admin_toggle_restriction(client_id):
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("client_dashboard"))

    client = User.query.get_or_404(client_id)

    if client.is_admin:
        flash("Cannot restrict admin accounts.", "danger")
        return redirect(url_for("admin_clients"))

    client.is_restricted = not client.is_restricted
    db.session.commit()

    status = "restricted" if client.is_restricted else "unrestricted"
    flash(f"Client account has been {status}.", "success")
    return redirect(url_for("admin_clients"))






@app.route("/admin/delete_client/<int:client_id>", methods=["POST"])
@login_required
def admin_delete_client(client_id):
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("client_dashboard"))

    csrf_token = request.form.get('csrf_token')
    try:
        validate_csrf(csrf_token)
    except ValidationError:
        flash("CSRF validation failed. Please try again.", "danger")
        return redirect(url_for("admin_clients"))

    client = User.query.get_or_404(client_id)

    # Delete all documents
    documents = Document.query.filter_by(user_id=client.id).all()
    for document in documents:
        try:
            if os.path.exists(document.filepath):
                os.remove(document.filepath)
        except Exception as e:
            logging.error(f"Error deleting file {document.filepath}: {e}")
        db.session.delete(document)

    # Delete all messages
    Message.query.filter(
        (Message.sender_id == client.id) | (Message.recipient_id == client.id)
    ).delete()

    # Delete the client
    db.session.delete(client)
    db.session.commit()

    flash(f"Client '{client.name}' has been deleted.", "success")
    return redirect(url_for("admin_clients"))






@app.route("/admin/documents", methods=["GET", "POST"])
@login_required
def admin_documents():
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("client_dashboard"))

    form = AdminDocumentUploadForm()

    # Populate client choices for the form
    clients = User.query.filter_by(is_admin=False).order_by(User.name).all()
    form.client.choices = [(client.id, client.name) for client in clients]

    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)

        # Generate unique filename
        unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)

        # Save the file
        file.save(filepath)

        # Create document record
        document = Document(
            filename=filename,
            filepath=filepath,
            description=form.description.data,
            is_admin_upload=True,
            user_id=form.client.data
        )

        db.session.add(document)
        db.session.commit()

        # Notify client about new document
        client = User.query.get(form.client.data)
        try:
            send_message_notification(
                client.email,
                "New document available",
                f"A new document '{filename}' has been uploaded for you. Please log in to access it."
            )
        except Exception as e:
            logging.error(f"Failed to send email notification: {e}")

        flash("Document uploaded successfully.", "success")
        return redirect(url_for("admin_documents"))

    # Get client and admin uploaded documents
    client_uploads = Document.query.filter_by(
        is_admin_upload=False
    ).order_by(Document.uploaded_at.desc()).all()

    admin_uploads = Document.query.filter_by(
        is_admin_upload=True
    ).order_by(Document.uploaded_at.desc()).all()

    return render_template(
        "admin/documents.html",
        form=form,
        client_uploads=client_uploads,
        admin_uploads=admin_uploads
    )


@app.route("/admin/messages", methods=["GET", "POST"])
@login_required
def admin_messages():
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("client_dashboard"))

    form = AdminMessageForm()

    # Populate client choices for the form
    clients = User.query.filter_by(is_admin=False).order_by(User.name).all()
    form.recipient.choices = [(client.id, client.name) for client in clients]

    if form.validate_on_submit():
        content = form.content.data
        is_group = form.is_group.data

        if is_group:
            # Send to all clients
            for client in clients:
                message = Message(
                    content=content,
                    sender_id=current_user.id,
                    recipient_id=client.id,
                    is_group_message=True
                )
                db.session.add(message)

                # Send notification email
                try:
                    send_message_notification(
                        client.email,
                        "New message from MR PROJECT",
                        "You have a new message from our team. Please log in to view it."
                    )
                except Exception as e:
                    logging.error(f"Failed to send email notification to {client.email}: {e}")

            flash("Group message sent to all clients.", "success")
        else:
            # Send to specific client
            recipient_id = form.recipient.data
            client = User.query.get_or_404(recipient_id)

            message = Message(
                content=content,
                sender_id=current_user.id,
                recipient_id=recipient_id
            )
            db.session.add(message)

            # Send notification email
            try:
                send_message_notification(
                    client.email,
                    "New message from MR PROJECT",
                    "You have a new message from our team. Please log in to view it."
                )
            except Exception as e:
                logging.error(f"Failed to send email notification: {e}")

            flash(f"Message sent to {client.name}.", "success")

        db.session.commit()
        return redirect(url_for("admin_messages"))

    # Get received and sent messages
    received_messages = Message.query.filter_by(
        recipient_id=current_user.id
    ).order_by(Message.created_at.desc()).all()

    sent_messages = Message.query.filter_by(
        sender_id=current_user.id
    ).order_by(Message.created_at.desc()).all()

    # Add recipients to sent messages (for display purposes)
    for message in sent_messages:
        if message.recipient_id:
            message.recipients = [User.query.get(message.recipient_id)]
        else:
            message.recipients = []

    # Mark received messages as read
    for message in received_messages:
        if not message.is_read:
            message.is_read = True

    db.session.commit()

    return render_template(
        "admin/messages.html",
        form=form,
        received_messages=received_messages,
        sent_messages=sent_messages
    )


# Error handlers
@app.errorhandler(404)
def page_not_found(error):
    return render_template("errors/404.html"), 404


@app.errorhandler(403)
def forbidden(error):
    return render_template("errors/403.html"), 403


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("errors/500.html"), 500







# ------------------ Voice Note Feature ------------------

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    """Serve uploaded audio files from the uploads folder."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)


@app.route("/upload_voice", methods=["POST"])
@login_required
def upload_voice():
    """Receive and save a voice note upload."""
    if "voice" not in request.files:
        return jsonify({"error": "No voice file provided"}), 400

    voice = request.files["voice"]

    print("Received file:", voice.filename, flush=True)

    if not voice or voice.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # Create a safe unique filename
    original = secure_filename(voice.filename)
    unique = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(6)}_{original}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
    voice.save(save_path)

    # Create a DB record
    recipient_id = request.form.get("recipient_id")
    if recipient_id:
        recipient = User.query.get(int(recipient_id))
    else:
        recipient = User.query.filter_by(is_admin=True).first()

    msg = Message(
        content=f"[VOICE]:{unique}",
        sender_id=current_user.id,
        recipient_id=recipient.id if recipient else None
    )
    db.session.add(msg)
    db.session.commit()

    return jsonify({
        "message": "uploaded",
        "url": url_for("uploaded_file", filename=unique),
        "db_record": True
    }), 200


# End of appended voice-note feature
