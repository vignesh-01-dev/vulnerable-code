<?php
// Secure File Upload Handler
class SecureFileUploadHandler {
    private $target_dir;
    private $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    private $max_file_size = 5242880; // 5MB
    private $allowed_mime_types = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf'
    ];
    private $upload_errors = [];
    
    public function __construct($upload_dir = 'uploads/') {
        // Validate and sanitize upload directory
        $upload_dir = realpath($upload_dir);
        if ($upload_dir === false) {
            throw new Exception('Invalid upload directory');
        }
        
        // Ensure upload directory is within web root
        $web_root = realpath($_SERVER['DOCUMENT_ROOT']);
        if (strpos($upload_dir, $web_root) !== 0) {
            throw new Exception('Upload directory must be within web root');
        }
        
        $this->target_dir = $upload_dir;
        
        // Create directory with secure permissions if it doesn't exist
        if (!file_exists($this->target_dir)) {
            if (!mkdir($this->target_dir, 0750, true)) {
                throw new Exception('Failed to create upload directory');
            }
        }
        
        // Ensure directory permissions are correct
        if (substr(sprintf('%o', fileperms($this->target_dir)), -4) !== '0750') {
            chmod($this->target_dir, 0750);
        }
    }
    
    private function validateFileSize($file) {
        if ($file['size'] > $this->max_file_size) {
            $this->upload_errors[] = 'File size exceeds maximum limit of 5MB';
            return false;
        }
        return true;
    }
    
    private function validateFileType($file) {
        // Use finfo to get real MIME type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if (!in_array($mime_type, $this->allowed_mime_types)) {
            $this->upload_errors[] = 'Invalid file type';
            return false;
        }
        
        return true;
    }
    
    private function validateExtension($filename) {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        // Check against allowed extensions
        if (!in_array($ext, $this->allowed_extensions)) {
            $this->upload_errors[] = 'File extension not allowed';
            return false;
        }
        
        // Check for double extensions
        if (substr_count($filename, '.') > 1) {
            $this->upload_errors[] = 'Double extensions not allowed';
            return false;
        }
        
        return true;
    }
    
    private function generateSecureFilename($original_filename) {
        // Get file extension
        $ext = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));
        
        // Generate random filename
        $random_bytes = bin2hex(random_bytes(16));
        $timestamp = time();
        
        return $timestamp . '_' . $random_bytes . '.' . $ext;
    }
    
    private function sanitizeFilename($filename) {
        // Remove any path traversal attempts
        $filename = basename($filename);
        
        // Remove any null bytes
        $filename = str_replace("\0", '', $filename);
        
        // Remove any non-printable characters
        $filename = preg_replace('/[\x00-\x1F\x7F]/', '', $filename);
        
        return $filename;
    }
    
    public function handleUpload() {
        try {
            // Check if file was uploaded
            if (!isset($_FILES["fileToUpload"]) || $_FILES["fileToUpload"]["error"] !== UPLOAD_ERR_OK) {
                throw new Exception('No file uploaded or upload error occurred');
            }
            
            $file = $_FILES["fileToUpload"];
            
            // Validate file size
            if (!$this->validateFileSize($file)) {
                throw new Exception(implode(', ', $this->upload_errors));
            }
            
            // Validate file type
            if (!$this->validateFileType($file)) {
                throw new Exception(implode(', ', $this->upload_errors));
            }
            
            // Sanitize and validate filename
            $original_filename = $this->sanitizeFilename($file["name"]);
            if (!$this->validateExtension($original_filename)) {
                throw new Exception(implode(', ', $this->upload_errors));
            }
            
            // Generate secure filename
            $secure_filename = $this->generateSecureFilename($original_filename);
            $target_file = $this->target_dir . $secure_filename;
            
            // Move uploaded file
            if (!move_uploaded_file($file["tmp_name"], $target_file)) {
                throw new Exception('Failed to move uploaded file');
            }
            
            // Set secure file permissions
            chmod($target_file, 0640);
            
            return [
                'success' => true,
                'filename' => $secure_filename,
                'message' => 'File uploaded successfully'
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        }
    }
}

// Start session for CSRF protection
session_start();

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }
    
    try {
        $uploader = new SecureFileUploadHandler();
        $result = $uploader->handleUpload();
        
        // Return JSON response
        header('Content-Type: application/json');
        echo json_encode($result);
        exit;
    } catch (Exception $e) {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
        exit;
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Secure File Upload</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            padding: 20px;
            max-width: 800px;
            margin: 0 auto;
        }
        .upload-form { 
            border: 1px solid #ccc; 
            padding: 20px; 
            border-radius: 5px;
            background-color: #f9f9f9;
        }
        .error { color: red; }
        .success { color: green; }
        #uploadStatus {
            margin-top: 20px;
            padding: 10px;
            border-radius: 5px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="upload-form">
        <h2>Secure File Upload Form</h2>
        <form id="uploadForm" method="post" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="file" name="fileToUpload" id="fileToUpload" required>
            <input type="submit" value="Upload File">
        </form>
        <div id="uploadStatus"></div>
    </div>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const statusDiv = document.getElementById('uploadStatus');
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                statusDiv.style.display = 'block';
                statusDiv.className = data.success ? 'success' : 'error';
                statusDiv.textContent = data.message;
            })
            .catch(error => {
                statusDiv.style.display = 'block';
                statusDiv.className = 'error';
                statusDiv.textContent = 'An error occurred during upload';
            });
        });
    </script>
</body>
</html>
