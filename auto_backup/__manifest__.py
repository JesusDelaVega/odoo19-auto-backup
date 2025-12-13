# -*- coding: utf-8 -*-
{
    'name': 'Auto Database Backup Pro',
    'version': '19.0.2.2.0',
    'author': 'Jose de Jesus De la Vega Garcia',
    'website': 'https://github.com/JesusDelaVega',
    'maintainer': 'Jose de Jesus De la Vega Garcia',
    'support': 'programador@outlook.es',
    'category': 'Administration',
    'license': 'LGPL-3',
    'price': 79.00,
    'currency': 'USD',

    'summary': 'Professional automatic database backups to Local, FTP, SFTP, Amazon S3, Google Drive with encryption',

    'description': """
Auto Database Backup Pro - Enterprise Backup Solution
======================================================

The most complete backup solution for Odoo 19!
Protect your business data with automatic scheduled backups.

KEY FEATURES
------------
* SCHEDULING
  - Hourly backups (every X hours)
  - Daily backups at specific time
  - Weekly backups on selected day
  - Monthly backups on selected date

* STORAGE DESTINATIONS
  - Local server storage
  - FTP / SFTP servers
  - Amazon S3 (and compatible: DigitalOcean Spaces, MinIO, Wasabi)
  - Google Drive (via Service Account)

* SECURITY
  - AES-256 encryption for backups
  - Password-protected backup files
  - Secure credential storage

* ADDITIONAL FEATURES
  - Multi-destination (cloud + local copy)
  - Email notifications (success/failure)
  - Automatic cleanup of old backups
  - Backup retention policies
  - One-click manual backup
  - Download backups from UI
  - Complete backup history
  - Statistics dashboard
  - Success rate tracking

BACKUP FORMATS
--------------
* ZIP: Complete backup with filestore (attachments, images)
* SQL Dump: Lightweight database-only backup

PERFECT FOR
-----------
* System administrators
* Companies needing data protection
* Compliance requirements (GDPR, SOC2)
* Disaster recovery planning
* Multi-site backup strategies

OPTIONAL DEPENDENCIES
---------------------
Install based on your needs:
* paramiko - For SFTP support
* boto3 - For Amazon S3/compatible storage
* google-api-python-client, google-auth - For Google Drive
* cryptography - For backup encryption

LANGUAGES SUPPORTED
-------------------
* English (en)
* Espanol (es)

Author: Jose de Jesus De la Vega Garcia
Professional Odoo Developer
""",

    'depends': ['base', 'mail'],
    'data': [
        'security/backup_security.xml',
        'security/ir.model.access.csv',
        'views/backup_config_views.xml',
        'views/backup_menu.xml',
        'views/res_config_settings_views.xml',
        'data/cron_data.xml',
        'data/mail_template_data.xml',
    ],

    'images': [
        'static/description/banner.png',
        'static/description/icon.png',
        'static/description/screenshot1.png',
        'static/description/screenshot2.png',
        'static/description/screenshot3.png',
        'static/description/screenshot4.png',
        'static/description/screenshot5.png',
        'static/description/screenshot6.png',
    ],

    'external_dependencies': {
        'python': [],  # All dependencies are optional
    },

    'installable': True,
    'auto_install': False,
    'application': True,
    'sequence': 1,
}
