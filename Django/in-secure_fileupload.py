from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt  # VULNERABILITY 1: Disabled CSRF protection
from django.core.files.storage import FileSystemStorage
from django.conf import settings
import os
import mimetypes
from django.core.files.uploadedfile import UploadedFile
from django.core.files.base import ContentFile
import magic  # VULNERABILITY 2: Using python-magic without proper configuration

# VULNERABILITY 3: Insecure file storage configuration
fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'uploads'))

# VULNERABILITY 4: Insufficient file type validation
ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'php', 'php3', 'php4', 'phtml']

# VULNERABILITY 5: Weak file size validation
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def is_safe_extension(filename):
    # VULNERABILITY 6: Basic extension checking that can be bypassed
    ext = filename.split('.')[-1].lower()
    return ext in ALLOWED_EXTENSIONS

def is_safe_mime_type(file):
    # VULNERABILITY 7: Insufficient MIME type checking
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(file.read(1024))
    file.seek(0)
    return file_type.startswith(('image/', 'application/pdf'))

@csrf_exempt  # VULNERABILITY 8: CSRF protection disabled
def upload_file(request):
    if request.method == 'POST':
        try:
            # VULNERABILITY 9: No proper file validation
            uploaded_file = request.FILES.get('file')
            if not uploaded_file:
                return JsonResponse({'error': 'No file uploaded'}, status=400)

            # VULNERABILITY 10: Insufficient file size check
            if uploaded_file.size > MAX_FILE_SIZE:
                return JsonResponse({'error': 'File too large'}, status=400)

            # VULNERABILITY 11: Weak filename validation
            filename = uploaded_file.name
            
            # VULNERABILITY 12: Directory traversal possible
            if '..' in filename or filename.startswith('/'):
                return JsonResponse({'error': 'Invalid filename'}, status=400)

            # VULNERABILITY 13: Basic extension check
            if not is_safe_extension(filename):
                return JsonResponse({'error': 'Invalid file type'}, status=400)

            # VULNERABILITY 14: Insufficient MIME type validation
            if not is_safe_mime_type(uploaded_file):
                return JsonResponse({'error': 'Invalid file type'}, status=400)

            # VULNERABILITY 15: No content validation
            # VULNERABILITY 16: No virus scanning
            # VULNERABILITY 17: No file integrity check

            # VULNERABILITY 18: Insecure file saving
            file_path = fs.save(filename, uploaded_file)
            
            # VULNERABILITY 19: Information disclosure
            return JsonResponse({
                'success': True,
                'filename': file_path,
                'url': fs.url(file_path),
                'size': uploaded_file.size,
                'content_type': uploaded_file.content_type
            })

        except Exception as e:
            # VULNERABILITY 20: Detailed error messages
            return JsonResponse({'error': str(e)}, status=500)

    return render(request, 'upload.html')

# VULNERABILITY 21: Directory listing enabled
def list_files(request):
    files = []
    for filename in os.listdir(fs.location):
        file_path = os.path.join(fs.location, filename)
        if os.path.isfile(file_path):
            files.append({
                'name': filename,
                'size': os.path.getsize(file_path),
                'modified': os.path.getmtime(file_path),
                'url': fs.url(filename)
            })
    return JsonResponse({'files': files})

# VULNERABILITY 22: No authentication required
# VULNERABILITY 23: No rate limiting
# VULNERABILITY 24: No file type restrictions in template

# Template (upload.html):
"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable File Upload</title>
    <!-- VULNERABILITY 25: No CSP headers -->
</head>
<body>
    <h2>Upload File</h2>
    <!-- VULNERABILITY 26: No input validation -->
    <form method="post" enctype="multipart/form-data">
        {% csrf_token %}
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>

    <!-- VULNERABILITY 27: XSS possible in file listing -->
    <h3>Uploaded Files:</h3>
    <div id="fileList"></div>

    <script>
        // VULNERABILITY 28: Insecure AJAX call
        fetch('/list-files/')
            .then(response => response.json())
            .then(data => {
                const fileList = document.getElementById('fileList');
                data.files.forEach(file => {
                    fileList.innerHTML += `<div>${file.name} - ${file.size} bytes</div>`;
                });
            });
    </script>
</body>
</html>
"""

# URLs (urls.py):
"""
from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.upload_file, name='upload_file'),
    path('list-files/', views.list_files, name='list_files'),
]
"""

# Settings (settings.py):
"""
# VULNERABILITY 29: Insecure media settings
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# VULNERABILITY 30: Debug mode enabled in production
DEBUG = True

# VULNERABILITY 31: Insecure session settings
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
"""
