# -*- coding: utf-8 -*-
import os
import logging
from odoo import http
from odoo.http import request, content_disposition

_logger = logging.getLogger(__name__)


class BackupDownloadController(http.Controller):

    @http.route('/backup/download/<int:history_id>/<string:token>', type='http', auth='user')
    def download_backup(self, history_id, token, **kwargs):
        """Download backup file with token verification"""
        # Get history record
        history = request.env['auto.backup.history'].sudo().browse(history_id)

        if not history.exists():
            return request.not_found()

        # Verify token
        if not history.download_token or history.download_token != token:
            return request.not_found()

        # Check file exists
        if not history.file_path or not os.path.exists(history.file_path):
            return request.not_found()

        # Clear token after use (one-time download)
        history.download_token = False

        # Serve file
        try:
            with open(history.file_path, 'rb') as f:
                file_content = f.read()

            filename = history.filename or os.path.basename(history.file_path)

            return request.make_response(
                file_content,
                headers=[
                    ('Content-Type', 'application/octet-stream'),
                    ('Content-Disposition', content_disposition(filename)),
                    ('Content-Length', len(file_content)),
                ]
            )
        except Exception as e:
            _logger.error(f"Error downloading backup: {str(e)}")
            return request.not_found()
