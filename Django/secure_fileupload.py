from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.core.validators import FileExtensionValidator
from django.core.files.uploadedfile import UploadedFile
from django.core.files.base import ContentFile
from django.utils import timezone
import os
import magic
import hashlib
import logging
from typing import List, Dict, Any
import re
from django.core.cache import cache
from django.views.generic import View
from django.urls import reverse
from django.contrib import messages
from django.http import HttpResponseForbidden
import clamd
from django.core.files.uploadhandler import TemporaryFileUploadHandler
from django.core.files.uploadedfile import TemporaryUploadedFile
import uuid

logger = logging.getLogger(__name__)

class SecureFileStorage(FileSystemStorage):
    """Secure file storage with additional security measures"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf']
        self.max_file_size = 5 * 1024 * 1024  # 5MB
        self.allowed_mime_types = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'application/pdf'
        ]
        
    def get_valid_name(self, name: str) -> str:
        """Generate a secure filename"""
        # Remove any path traversal attempts
        name = os.path.basename(name)
        
        # Generate a unique filename
        ext = os.path.splitext(name)[1].lower()
        if ext not in [f'.{ext}' for ext in self.allowed_extensions]:
            raise ValidationError('Invalid file extension')
            
        unique_id = str(uuid.uuid4())
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        return f"{timestamp}_{unique_id}{ext}"
    
    def get_available_name(self, name: str) -> str:
        """Ensure unique filename"""
        return self.get_valid_name(name)

class SecureFileUploadHandler(TemporaryFileUploadHandler):
    """Custom upload handler with security checks"""
    
    def receive_data_chunk(self, raw_data, start):
        """Validate chunks during upload"""
        if start == 0:
            # Check file signature
            mime = magic.Magic(mime=True)
            file_type = mime.from_buffer(raw_data[:1024])
            if not file_type.startswith(('image/', 'application/pdf')):
                raise ValidationError('Invalid file type')
        
        return super().receive_data_chunk(raw_data, start)

class FileUploadView(View):
    """Secure file upload view with multiple security layers"""
    
    storage = SecureFileStorage(
        location=os.path.join(settings.MEDIA_ROOT, 'secure_uploads'),
        base_url='/secure-media/'
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clam = clamd.ClamdUnixSocket()
    
    @method_decorator(login_required)
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def validate_file(self, file: UploadedFile) -> None:
        """Comprehensive file validation"""
        # Check file size
        if file.size > self.storage.max_file_size:
            raise ValidationError('File too large')
        
        # Validate file extension
        ext = os.path.splitext(file.name)[1].lower()
        if ext not in [f'.{ext}' for ext in self.storage.allowed_extensions]:
            raise ValidationError('Invalid file extension')
        
        # Validate MIME type
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(file.read(1024))
        file.seek(0)
        
        if file_type not in self.storage.allowed_mime_types:
            raise ValidationError('Invalid file type')
        
        # Scan for viruses
        try:
            scan_result = self.clam.instream(file)
            if scan_result[0] != 'OK':
                raise ValidationError('File contains malware')
        except Exception as e:
            logger.error(f"Virus scan failed: {str(e)}")
            raise ValidationError('Security check failed')
        
        # Calculate file hash for integrity check
        sha256_hash = hashlib.sha256()
        for chunk in file.chunks():
            sha256_hash.update(chunk)
        file.seek(0)
        
        # Store hash for later verification
        cache.set(f"file_hash_{file.name}", sha256_hash.hexdigest(), timeout=3600)
    
    def post(self, request, *args, **kwargs):
        """Handle file upload with security measures"""
        try:
            # Rate limiting check
            cache_key = f"upload_rate_{request.user.id}"
            if cache.get(cache_key):
                return JsonResponse({
                    'error': 'Upload rate limit exceeded'
                }, status=429)
            
            # Set rate limit
            cache.set(cache_key, True, timeout=60)
            
            # Get uploaded file
            uploaded_file = request.FILES.get('file')
            if not uploaded_file:
                return JsonResponse({
                    'error': 'No file uploaded'
                }, status=400)
            
            # Validate file
            self.validate_file(uploaded_file)
            
            # Generate secure filename
            secure_filename = self.storage.get_valid_name(uploaded_file.name)
            
            # Save file with secure permissions
            file_path = self.storage.save(secure_filename, uploaded_file)
            os.chmod(os.path.join(self.storage.location, file_path), 0o640)
            
            # Log successful upload
            logger.info(f"File uploaded successfully: {file_path} by user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'filename': secure_filename,
                'size': uploaded_file.size,
                'message': 'File uploaded successfully'
            })
            
        except ValidationError as e:
            logger.warning(f"File upload validation failed: {str(e)}")
            return JsonResponse({
                'error': str(e)
            }, status=400)
            
        except Exception as e:
            logger.error(f"File upload failed: {str(e)}")
            return JsonResponse({
                'error': 'An error occurred during upload'
            }, status=500)
    
    def get(self, request, *args, **kwargs):
        """Render upload form with security headers"""
        response = render(request, 'secure_upload.html')
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
        return response

# URLs (urls.py):
"""
from django.urls import path
from .views import FileUploadView

urlpatterns = [
    path('secure-upload/', FileUploadView.as_view(), name='secure_upload'),
]
"""

# Template (secure_upload.html):
"""
{% extends "base.html" %}

{% block content %}
<div class="upload-container">
    <h2>Secure File Upload</h2>
    
    <form id="uploadForm" method="post" enctype="multipart/form-data">
        {% csrf_token %}
        <div class="form-group">
            <label for="file">Select File:</label>
            <input type="file" name="file" id="file" required 
                   accept=".jpg,.jpeg,.png,.gif,.pdf">
        </div>
        <button type="submit" class="btn btn-primary">Upload</button>
    </form>
    
    <div id="uploadStatus" class="alert" style="display: none;"></div>
</div>

<script>
document.getElementById('uploadForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const statusDiv = document.getElementById('uploadStatus');
    
    try {
        const response = await fetch('{% url "secure_upload" %}', {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        });
        
        const data = await response.json();
        
        statusDiv.style.display = 'block';
        statusDiv.className = data.success ? 'alert alert-success' : 'alert alert-danger';
        statusDiv.textContent = data.message || data.error;
        
    } catch (error) {
        statusDiv.style.display = 'block';
        statusDiv.className = 'alert alert-danger';
        statusDiv.textContent = 'An error occurred during upload';
    }
});
</script>
{% endblock %}
"""

# Settings (settings.py):
"""
# Security Settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# File Upload Settings
FILE_UPLOAD_HANDLERS = [
    'django.core.files.uploadhandler.MemoryFileUploadHandler',
    'django.core.files.uploadhandler.TemporaryFileUploadHandler',
]

# Media Settings
MEDIA_URL = '/secure-media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'secure_media')

# Debug Settings
DEBUG = False

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/file_upload.log',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
"""
