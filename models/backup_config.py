# -*- coding: utf-8 -*-
import os
import io
import base64
import time
import logging
import tempfile
import shutil
import hashlib
from datetime import datetime, timedelta

from odoo import models, fields, api, tools, _
from odoo.exceptions import UserError
from odoo.service import db

_logger = logging.getLogger(__name__)

# Optional dependencies
try:
    import paramiko
    PARAMIKO_INSTALLED = True
except ImportError:
    PARAMIKO_INSTALLED = False
    _logger.warning("paramiko not installed. SFTP backup will not be available.")

try:
    from ftplib import FTP
    FTP_AVAILABLE = True
except ImportError:
    FTP_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    _logger.info("cryptography not installed. Encryption will not be available.")

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    _logger.info("boto3 not installed. S3 backup will not be available.")

try:
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False
    _logger.info("google-api-python-client not installed. Google Drive will not be available.")


class BackupConfig(models.Model):
    _name = 'auto.backup.config'
    _description = 'Automatic Backup Configuration'
    _inherit = ['mail.thread', 'mail.activity.mixin']

    name = fields.Char(
        string='Backup Name',
        required=True,
        tracking=True,
        help="A descriptive name for this backup configuration"
    )
    active = fields.Boolean(default=True, tracking=True)

    # Database
    database_name = fields.Char(
        string='Database Name',
        required=True,
        default=lambda self: self._cr.dbname,
        help="Name of the database to backup"
    )

    # Backup Type
    backup_format = fields.Selection([
        ('zip', 'Zip (includes filestore)'),
        ('dump', 'SQL Dump (database only)'),
    ], string='Backup Format', default='zip', required=True,
       help="Zip includes filestore, SQL Dump is smaller but without files")

    # Schedule
    backup_frequency = fields.Selection([
        ('hourly', 'Every X Hours'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ], string='Frequency', default='daily', required=True, tracking=True)

    backup_hour_interval = fields.Integer(
        string='Every X Hours',
        default=6,
        help="Run backup every X hours (for hourly frequency)"
    )

    backup_time = fields.Float(
        string='Backup Time',
        default=2.0,
        help="Time to run backup (in 24h format, e.g., 2.0 = 02:00 AM)"
    )

    backup_day_of_week = fields.Selection([
        ('0', 'Monday'),
        ('1', 'Tuesday'),
        ('2', 'Wednesday'),
        ('3', 'Thursday'),
        ('4', 'Friday'),
        ('5', 'Saturday'),
        ('6', 'Sunday'),
    ], string='Day of Week', default='0',
       help="Day to run weekly backups")

    backup_day_of_month = fields.Integer(
        string='Day of Month',
        default=1,
        help="Day of month to run monthly backups (1-28)"
    )

    # Storage Destination
    storage_type = fields.Selection([
        ('local', 'Local Server'),
        ('ftp', 'FTP Server'),
        ('sftp', 'SFTP Server'),
        ('s3', 'Amazon S3 / Compatible'),
        ('google_drive', 'Google Drive'),
    ], string='Storage Type', default='local', required=True, tracking=True)

    # Local Storage
    local_path = fields.Char(
        string='Local Path',
        default='/tmp/odoo_backups',
        help="Path on the server to store backups"
    )

    # FTP/SFTP Settings
    ftp_host = fields.Char(string='FTP/SFTP Host')
    ftp_port = fields.Integer(string='Port', default=21)
    ftp_user = fields.Char(string='Username')
    ftp_password = fields.Char(string='Password')
    ftp_path = fields.Char(string='Remote Path', default='/backups')

    # Amazon S3 Settings
    s3_access_key = fields.Char(string='Access Key ID')
    s3_secret_key = fields.Char(string='Secret Access Key')
    s3_bucket = fields.Char(string='Bucket Name')
    s3_region = fields.Char(string='Region', default='us-east-1')
    s3_endpoint = fields.Char(
        string='Custom Endpoint',
        help="Leave empty for AWS S3. For compatible services (DigitalOcean, MinIO, Wasabi), enter the endpoint URL."
    )
    s3_path = fields.Char(string='Path/Prefix', default='odoo-backups/')

    # Google Drive Settings
    google_drive_folder_id = fields.Char(
        string='Folder ID',
        help="ID of the Google Drive folder where backups will be stored"
    )
    google_drive_credentials = fields.Text(
        string='Service Account JSON',
        help="Paste the content of your Google Service Account JSON file"
    )

    # Encryption Settings
    encrypt_backup = fields.Boolean(
        string='Encrypt Backup',
        default=False,
        help="Encrypt backup file with AES-256 encryption"
    )
    encryption_password = fields.Char(
        string='Encryption Password',
        help="Password used to encrypt/decrypt backups"
    )

    # Multi-destination (save to local + cloud)
    also_save_local = fields.Boolean(
        string='Also Save Locally',
        default=False,
        help="Keep a local copy in addition to remote storage"
    )

    # Retention
    backup_retention = fields.Integer(
        string='Keep Backups (days)',
        default=30,
        help="Number of days to keep backups. Older backups will be deleted automatically."
    )

    # Notifications
    notify_on_success = fields.Boolean(
        string='Notify on Success',
        default=False
    )
    notify_on_failure = fields.Boolean(
        string='Notify on Failure',
        default=True
    )
    notification_emails = fields.Char(
        string='Notification Emails',
        help="Comma-separated list of emails to notify"
    )

    # Status
    last_backup_date = fields.Datetime(
        string='Last Backup',
        readonly=True
    )
    last_backup_status = fields.Selection([
        ('success', 'Success'),
        ('failed', 'Failed'),
    ], string='Last Status', readonly=True)
    last_backup_message = fields.Text(
        string='Last Message',
        readonly=True
    )
    last_backup_size = fields.Char(
        string='Last Backup Size',
        readonly=True
    )

    # Backup History
    backup_history_ids = fields.One2many(
        'auto.backup.history',
        'config_id',
        string='Backup History'
    )
    backup_count = fields.Integer(
        string='Total Backups',
        compute='_compute_backup_stats'
    )

    # Statistics
    success_count = fields.Integer(
        string='Successful Backups',
        compute='_compute_backup_stats'
    )
    failed_count = fields.Integer(
        string='Failed Backups',
        compute='_compute_backup_stats'
    )
    success_rate = fields.Float(
        string='Success Rate (%)',
        compute='_compute_backup_stats'
    )
    total_size_bytes = fields.Float(
        string='Total Size (bytes)',
        compute='_compute_backup_stats'
    )
    avg_size = fields.Char(
        string='Average Backup Size',
        compute='_compute_backup_stats'
    )
    next_backup = fields.Char(
        string='Next Scheduled Backup',
        compute='_compute_next_backup'
    )

    @api.depends('backup_history_ids', 'backup_history_ids.status', 'backup_history_ids.file_size')
    def _compute_backup_stats(self):
        for record in self:
            history = record.backup_history_ids
            record.backup_count = len(history)
            record.success_count = len(history.filtered(lambda h: h.status == 'success'))
            record.failed_count = len(history.filtered(lambda h: h.status == 'failed'))
            record.success_rate = (record.success_count / record.backup_count * 100) if record.backup_count else 0

            # Calculate total and average size
            total_bytes = 0
            count = 0
            for h in history.filtered(lambda x: x.file_size_bytes):
                total_bytes += h.file_size_bytes
                count += 1
            record.total_size_bytes = total_bytes
            record.avg_size = record._format_size(total_bytes / count) if count else '0 B'

    @api.depends('backup_frequency', 'backup_time', 'backup_day_of_week', 'backup_day_of_month', 'backup_hour_interval')
    def _compute_next_backup(self):
        for record in self:
            now = datetime.now()
            hour = int(record.backup_time)
            minute = int((record.backup_time % 1) * 60)

            if record.backup_frequency == 'hourly':
                next_run = now.replace(minute=0, second=0) + timedelta(hours=record.backup_hour_interval)
            elif record.backup_frequency == 'daily':
                next_run = now.replace(hour=hour, minute=minute, second=0)
                if next_run <= now:
                    next_run += timedelta(days=1)
            elif record.backup_frequency == 'weekly':
                days_ahead = int(record.backup_day_of_week or 0) - now.weekday()
                if days_ahead < 0 or (days_ahead == 0 and now.hour >= hour):
                    days_ahead += 7
                next_run = now.replace(hour=hour, minute=minute, second=0) + timedelta(days=days_ahead)
            elif record.backup_frequency == 'monthly':
                day = min(record.backup_day_of_month or 1, 28)
                next_run = now.replace(day=day, hour=hour, minute=minute, second=0)
                if next_run <= now:
                    if now.month == 12:
                        next_run = next_run.replace(year=now.year + 1, month=1)
                    else:
                        next_run = next_run.replace(month=now.month + 1)
            else:
                next_run = now

            record.next_backup = next_run.strftime('%Y-%m-%d %H:%M')

    def _get_backup_filename(self):
        """Generate backup filename with timestamp"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        extension = 'zip' if self.backup_format == 'zip' else 'sql'
        return f"{self.database_name}_{timestamp}.{extension}"

    def _format_size(self, size_bytes):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"

    def action_test_connection(self):
        """Test connection to storage destination"""
        self.ensure_one()
        try:
            if self.storage_type == 'local':
                if not os.path.exists(self.local_path):
                    os.makedirs(self.local_path, exist_ok=True)
                # Test write permission
                test_file = os.path.join(self.local_path, '.test_write')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                message = _("Local path is accessible and writable!")

            elif self.storage_type == 'ftp':
                ftp = FTP()
                ftp.connect(self.ftp_host, self.ftp_port)
                ftp.login(self.ftp_user, self.ftp_password)
                ftp.cwd(self.ftp_path)
                ftp.quit()
                message = _("FTP connection successful!")

            elif self.storage_type == 'sftp':
                if not PARAMIKO_INSTALLED:
                    raise UserError(_("Please install paramiko: pip install paramiko"))
                transport = paramiko.Transport((self.ftp_host, self.ftp_port or 22))
                transport.connect(username=self.ftp_user, password=self.ftp_password)
                sftp = paramiko.SFTPClient.from_transport(transport)
                sftp.listdir(self.ftp_path)
                sftp.close()
                transport.close()
                message = _("SFTP connection successful!")

            elif self.storage_type == 's3':
                if not BOTO3_AVAILABLE:
                    raise UserError(_("Please install boto3: pip install boto3"))
                config = {
                    'aws_access_key_id': self.s3_access_key,
                    'aws_secret_access_key': self.s3_secret_key,
                    'region_name': self.s3_region or 'us-east-1',
                }
                if self.s3_endpoint:
                    config['endpoint_url'] = self.s3_endpoint
                s3_client = boto3.client('s3', **config)
                s3_client.head_bucket(Bucket=self.s3_bucket)
                message = _("S3 connection successful!")

            elif self.storage_type == 'google_drive':
                if not GOOGLE_AVAILABLE:
                    raise UserError(_("Please install: pip install google-api-python-client google-auth"))
                import json
                from google.oauth2 import service_account
                creds_info = json.loads(self.google_drive_credentials)
                credentials = service_account.Credentials.from_service_account_info(
                    creds_info,
                    scopes=['https://www.googleapis.com/auth/drive.file']
                )
                service = build('drive', 'v3', credentials=credentials)
                # Test by listing files in folder
                if self.google_drive_folder_id:
                    service.files().get(fileId=self.google_drive_folder_id).execute()
                message = _("Google Drive connection successful!")

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Connection Test'),
                    'message': message,
                    'type': 'success',
                    'sticky': False,
                }
            }
        except Exception as e:
            raise UserError(_("Connection failed: %s") % str(e))

    def action_backup_now(self):
        """Execute backup immediately"""
        self.ensure_one()
        return self._execute_backup()

    def _execute_backup(self):
        """Main backup execution method"""
        self.ensure_one()
        backup_file = None
        temp_path = None
        success = False
        message = ""
        file_size = 0

        try:
            # Generate filename
            filename = self._get_backup_filename()

            # Create temp directory
            temp_path = tempfile.mkdtemp()
            backup_file = os.path.join(temp_path, filename)

            _logger.info(f"Starting backup of {self.database_name} to {backup_file}")

            # Execute backup using Odoo's db service
            with open(backup_file, 'wb') as f:
                db.dump_db(self.database_name, f, self.backup_format)

            file_size = os.path.getsize(backup_file)
            _logger.info(f"Backup created: {filename} ({self._format_size(file_size)})")

            # Encrypt if enabled
            final_file = backup_file
            final_filename = filename
            if self.encrypt_backup:
                final_file = self._encrypt_file(backup_file)
                final_filename = filename + '.enc'
                file_size = os.path.getsize(final_file)

            # Upload to destination
            if self.storage_type == 'local':
                self._save_local(final_file, final_filename)
            elif self.storage_type == 'ftp':
                self._save_ftp(final_file, final_filename)
            elif self.storage_type == 'sftp':
                self._save_sftp(final_file, final_filename)
            elif self.storage_type == 's3':
                self._save_s3(final_file, final_filename)
            elif self.storage_type == 'google_drive':
                self._save_google_drive(final_file, final_filename)

            # Also save locally if enabled (multi-destination)
            if self.also_save_local and self.storage_type != 'local':
                self._save_local(final_file, final_filename)

            success = True
            message = _("Backup completed successfully: %s") % final_filename

            # Cleanup old backups
            self._cleanup_old_backups()

        except Exception as e:
            success = False
            message = _("Backup failed: %s") % str(e)
            _logger.error(f"Backup failed for {self.database_name}: {str(e)}")

        finally:
            # Clean temp files
            if temp_path and os.path.exists(temp_path):
                shutil.rmtree(temp_path)

        # Update status
        self.write({
            'last_backup_date': fields.Datetime.now(),
            'last_backup_status': 'success' if success else 'failed',
            'last_backup_message': message,
            'last_backup_size': self._format_size(file_size) if file_size else '',
        })

        # Determine file path for local storage
        saved_file_path = ''
        if success and self.storage_type == 'local':
            saved_file_path = os.path.join(self.local_path, final_filename)
        elif success and self.also_save_local:
            saved_file_path = os.path.join(self.local_path, final_filename)

        # Create history record
        self.env['auto.backup.history'].create({
            'config_id': self.id,
            'backup_date': fields.Datetime.now(),
            'status': 'success' if success else 'failed',
            'message': message,
            'file_size': self._format_size(file_size) if file_size else '',
            'file_size_bytes': file_size,
            'filename': final_filename if success else '',
            'file_path': saved_file_path,
            'encrypted': self.encrypt_backup if success else False,
        })

        # Send notifications
        self._send_notification(success, message)

        if success:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Backup Complete'),
                    'message': message,
                    'type': 'success',
                    'sticky': False,
                }
            }
        else:
            raise UserError(message)

    def _save_local(self, backup_file, filename):
        """Save backup to local storage"""
        if not os.path.exists(self.local_path):
            os.makedirs(self.local_path, exist_ok=True)
        destination = os.path.join(self.local_path, filename)
        shutil.copy2(backup_file, destination)
        _logger.info(f"Backup saved locally: {destination}")

    def _save_ftp(self, backup_file, filename):
        """Save backup to FTP server"""
        ftp = FTP()
        ftp.connect(self.ftp_host, self.ftp_port)
        ftp.login(self.ftp_user, self.ftp_password)
        ftp.cwd(self.ftp_path)
        with open(backup_file, 'rb') as f:
            ftp.storbinary(f'STOR {filename}', f)
        ftp.quit()
        _logger.info(f"Backup uploaded to FTP: {filename}")

    def _save_sftp(self, backup_file, filename):
        """Save backup to SFTP server"""
        if not PARAMIKO_INSTALLED:
            raise UserError(_("Please install paramiko: pip install paramiko"))
        transport = paramiko.Transport((self.ftp_host, self.ftp_port or 22))
        transport.connect(username=self.ftp_user, password=self.ftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        remote_path = os.path.join(self.ftp_path, filename)
        sftp.put(backup_file, remote_path)
        sftp.close()
        transport.close()
        _logger.info(f"Backup uploaded to SFTP: {remote_path}")

    def _save_s3(self, backup_file, filename):
        """Save backup to Amazon S3 or compatible storage"""
        if not BOTO3_AVAILABLE:
            raise UserError(_("Please install boto3: pip install boto3"))

        # Configure S3 client
        config = {
            'aws_access_key_id': self.s3_access_key,
            'aws_secret_access_key': self.s3_secret_key,
            'region_name': self.s3_region or 'us-east-1',
        }
        if self.s3_endpoint:
            config['endpoint_url'] = self.s3_endpoint

        s3_client = boto3.client('s3', **config)

        # Upload file
        s3_key = (self.s3_path or '') + filename
        s3_client.upload_file(backup_file, self.s3_bucket, s3_key)
        _logger.info(f"Backup uploaded to S3: s3://{self.s3_bucket}/{s3_key}")

    def _save_google_drive(self, backup_file, filename):
        """Save backup to Google Drive"""
        if not GOOGLE_AVAILABLE:
            raise UserError(_("Please install google packages: pip install google-api-python-client google-auth"))

        import json
        from google.oauth2 import service_account

        # Parse credentials
        try:
            creds_info = json.loads(self.google_drive_credentials)
            credentials = service_account.Credentials.from_service_account_info(
                creds_info,
                scopes=['https://www.googleapis.com/auth/drive.file']
            )
        except Exception as e:
            raise UserError(_("Invalid Google Drive credentials: %s") % str(e))

        # Build Drive service
        service = build('drive', 'v3', credentials=credentials)

        # Upload file
        file_metadata = {
            'name': filename,
            'parents': [self.google_drive_folder_id] if self.google_drive_folder_id else []
        }
        media = MediaFileUpload(backup_file, resumable=True)
        file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()

        _logger.info(f"Backup uploaded to Google Drive: {filename} (ID: {file.get('id')})")
        return file.get('id')

    def _encrypt_file(self, file_path):
        """Encrypt a file using AES-256"""
        if not CRYPTO_AVAILABLE:
            raise UserError(_("Please install cryptography: pip install cryptography"))

        if not self.encryption_password:
            raise UserError(_("Encryption password is required"))

        # Derive key from password
        salt = b'odoo_backup_salt'  # In production, use random salt and store it
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.encryption_password.encode()))
        fernet = Fernet(key)

        # Read and encrypt file
        with open(file_path, 'rb') as f:
            data = f.read()

        encrypted_data = fernet.encrypt(data)

        # Write encrypted file
        encrypted_path = file_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        _logger.info(f"Backup encrypted: {encrypted_path}")
        return encrypted_path

    def _decrypt_file(self, encrypted_path, output_path):
        """Decrypt a file"""
        if not CRYPTO_AVAILABLE:
            raise UserError(_("Please install cryptography: pip install cryptography"))

        if not self.encryption_password:
            raise UserError(_("Encryption password is required"))

        # Derive key from password
        salt = b'odoo_backup_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.encryption_password.encode()))
        fernet = Fernet(key)

        # Read and decrypt file
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return output_path

    def _cleanup_old_backups(self):
        """Remove backups older than retention period"""
        if not self.backup_retention:
            return

        cutoff_date = datetime.now() - timedelta(days=self.backup_retention)

        try:
            if self.storage_type == 'local':
                if os.path.exists(self.local_path):
                    for filename in os.listdir(self.local_path):
                        filepath = os.path.join(self.local_path, filename)
                        if os.path.isfile(filepath):
                            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                            if file_time < cutoff_date:
                                os.remove(filepath)
                                _logger.info(f"Deleted old backup: {filename}")

            elif self.storage_type == 'ftp':
                ftp = FTP()
                ftp.connect(self.ftp_host, self.ftp_port)
                ftp.login(self.ftp_user, self.ftp_password)
                ftp.cwd(self.ftp_path)
                for filename in ftp.nlst():
                    try:
                        mdtm = ftp.sendcmd(f'MDTM {filename}')
                        file_time = datetime.strptime(mdtm[4:], '%Y%m%d%H%M%S')
                        if file_time < cutoff_date:
                            ftp.delete(filename)
                            _logger.info(f"Deleted old FTP backup: {filename}")
                    except:
                        pass
                ftp.quit()

        except Exception as e:
            _logger.warning(f"Error cleaning old backups: {str(e)}")

    def _send_notification(self, success, message):
        """Send email notification"""
        if success and not self.notify_on_success:
            return
        if not success and not self.notify_on_failure:
            return
        if not self.notification_emails:
            return

        template = self.env.ref('auto_backup.mail_template_backup_notification', raise_if_not_found=False)
        if template:
            for email in self.notification_emails.split(','):
                email = email.strip()
                if email:
                    template.with_context(
                        backup_status='Success' if success else 'Failed',
                        backup_message=message,
                    ).send_mail(self.id, email_values={'email_to': email})

    @api.model
    def _cron_backup(self):
        """Cron job to execute scheduled backups"""
        configs = self.search([('active', '=', True)])
        for config in configs:
            try:
                config._execute_backup()
            except Exception as e:
                _logger.error(f"Scheduled backup failed for {config.name}: {str(e)}")


class BackupHistory(models.Model):
    _name = 'auto.backup.history'
    _description = 'Backup History'
    _order = 'backup_date desc'

    config_id = fields.Many2one(
        'auto.backup.config',
        string='Backup Configuration',
        required=True,
        ondelete='cascade'
    )
    backup_date = fields.Datetime(string='Date', required=True)
    status = fields.Selection([
        ('success', 'Success'),
        ('failed', 'Failed'),
    ], string='Status', required=True)
    message = fields.Text(string='Message')
    file_size = fields.Char(string='File Size')
    file_size_bytes = fields.Float(string='Size (bytes)')
    filename = fields.Char(string='Filename')
    file_path = fields.Char(string='File Path', help="Full path to backup file (for local storage)")
    storage_type = fields.Selection(related='config_id.storage_type', store=True)
    encrypted = fields.Boolean(string='Encrypted', default=False)

    # For downloads
    download_token = fields.Char(string='Download Token')

    def action_download_backup(self):
        """Download backup file"""
        self.ensure_one()

        if self.status != 'success':
            raise UserError(_("Cannot download failed backup"))

        if not self.file_path or not os.path.exists(self.file_path):
            raise UserError(_("Backup file not found on server. It may have been deleted or stored remotely."))

        # Generate download token
        import secrets
        token = secrets.token_urlsafe(32)
        self.download_token = token

        # Return download URL
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        download_url = f"{base_url}/backup/download/{self.id}/{token}"

        return {
            'type': 'ir.actions.act_url',
            'url': download_url,
            'target': 'self',
        }

    def action_delete_backup(self):
        """Delete backup file from storage"""
        self.ensure_one()

        if self.file_path and os.path.exists(self.file_path):
            try:
                os.remove(self.file_path)
                _logger.info(f"Deleted backup file: {self.file_path}")
            except Exception as e:
                _logger.error(f"Error deleting backup: {str(e)}")

        self.unlink()
        return {'type': 'ir.actions.act_window_close'}
