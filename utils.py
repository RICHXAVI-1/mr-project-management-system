import os
import string
import random
import logging
from datetime import datetime
from flask_mail import Message
from app import mail

def send_otp_email(recipient_email, otp_code, recipient_name):
    """
    Sends an OTP code to the user's email for verification.

    Args:
        recipient_email (str): The email address to send to
        otp_code (str): The OTP code
        recipient_name (str): The name of the recipient
    """
    try:
        subject = "Your MR PROJECT Verification Code"
        body = f"""
        Hello {recipient_name},

        Your verification code for MR PROJECT is: {otp_code}

        This code will expire in 10 minutes.

        If you did not request this code, please ignore this email.

        Thank you,
        MR PROJECT Team
        """

        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=body
        )

        mail.send(msg)
        logging.info(f"OTP email sent to {recipient_email}")
    except Exception as e:
        logging.error(f"Failed to send OTP email: {e}")
        raise


def send_message_notification(recipient_email, subject, message):
    """
    Sends a notification email when a new message is received.

    Args:
        recipient_email (str): The email address to send to
        subject (str): The email subject
        message (str): The email message
    """
    try:
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=message
        )

        mail.send(msg)
        logging.info(f"Notification email sent to {recipient_email}")
    except Exception as e:
        logging.error(f"Failed to send notification email: {e}")
        raise


def generate_approval_code(length=8):
    """
    Generates a random approval code.

    Args:
        length (int): The length of the code to generate

    Returns:
        str: A randomly generated approval code
    """
    # Use uppercase letters and digits for better readability
    characters = string.ascii_uppercase + string.digits

    # Exclude similar looking characters like O and 0, I and 1
    characters = characters.replace('O', '').replace('0', '').replace('I', '').replace('1', '')

    # Generate random code
    code = ''.join(random.choice(characters) for _ in range(length))

    # Add a timestamp prefix for uniqueness (use first 4 chars)
    timestamp_prefix = datetime.utcnow().strftime('%M%S')[:4]

    return f"{timestamp_prefix}{code}"


def allowed_file(filename):
    """
    Checks if a filename has an allowed extension.

    Args:
        filename (str): The filename to check

    Returns:
        bool: True if the file extension is allowed, False otherwise
    """
    # List of allowed file extensions
    ALLOWED_EXTENSIONS = {'doc', 'docx', 'pdf', 'txt', 'xlsx', 'pptx', 'zip'}

    # Check if the filename has a '.' and the extension is allowed
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def format_file_size(size_bytes):
    """
    Formats a file size in bytes to a human-readable string.

    Args:
        size_bytes (int): File size in bytes

    Returns:
        str: Formatted file size string (e.g., '2.5 MB')
    """
    # Define size units
    units = ['B', 'KB', 'MB', 'GB']

    # Calculate the appropriate unit
    unit_index = 0
    while size_bytes >= 1024 and unit_index < len(units) - 1:
        size_bytes /= 1024
        unit_index += 1

    # Format the result with 2 decimal places if needed
    if unit_index > 0:
        return f"{size_bytes:.2f} {units[unit_index]}"
    else:
        return f"{size_bytes} {units[unit_index]}"

def allowed_file(filename):
    """
    Checks if a filename has an allowed extension.
    """
    # List of allowed file extensions (added audio formats for voice notes)
    ALLOWED_EXTENSIONS = {
        'doc', 'docx', 'pdf', 'txt', 'xlsx', 'pptx', 'zip',
        'mp3', 'wav', 'webm', 'ogg', 'm4a'
    }

    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

