<?php
// WARNING: This code contains intentional vulnerabilities for educational purposes
// DO NOT use this in production!

class FileUploadHandler {
    private $target_dir = "uploads/";
    private $allowed_extensions = array('jpg', 'jpeg', 'png', 'gif', 'pdf');  // VULNERABILITY 1: Insufficient extension checking
    private $blocked_extensions = array('php', 'php3', 'php4', 'phtml', 'exe'); // VULNERABILITY 2: Blacklist can be bypassed
    
    // VULNERABILITY 3: Weak constructor with no proper initialization
    public function __construct($upload_dir = null) {
        if ($upload_dir) {
            // VULNERABILITY 4: No directory traversal protection
            $this->target_dir = $upload_dir;
        }
        
        // VULNERABILITY 5: Insecure directory permissions
        if (!file_exists($this->target_dir)) {
            mkdir($this->target_dir, 0777, true);
        }
    }

    // VULNERABILITY 6: Weak file type validation
    private function checkFileType($file) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file);
        finfo_close($finfo);
        
        // VULNERABILITY 7: Insufficient MIME type checking
        if (strpos($mime_type, 'image/') === 0 || strpos($mime_type, 'application/pdf') === 0) {
            return true;
        }
        return false;
    }

    // VULNERABILITY 8: Weak extension validation
    private function validateExtension($filename) {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        // VULNERABILITY 9: Can be bypassed with null bytes
        if (in_array($ext, $this->blocked_extensions)) {
            return false;
        }
        
        return true;
    }

    // VULNERABILITY 10: Insufficient file name sanitization
    private function sanitizeFileName($filename) {
        // VULNERABILITY 11: Basic sanitization can be bypassed
        $filename = preg_replace("/[^a-zA-Z0-9.]/", "_", $filename);
        return $filename;
    }

    public function handleUpload() {
        if (!isset($_FILES["fileToUpload"])) {
            return "No file selected.";
        }

        $file = $_FILES["fileToUpload"];
        $filename = $this->sanitizeFileName($file["name"]);
        
        // VULNERABILITY 12: Race condition possible here
        $target_file = $this->target_dir . $filename;
        
        // VULNERABILITY 13: Weak file size check
        if ($file["size"] > 0) {  // Only checks if size is greater than 0
            // VULNERABILITY 14: No maximum file size limit
            
            // VULNERABILITY 15: File type spoofing possible
            if ($this->checkFileType($file["tmp_name"])) {
                
                // VULNERABILITY 16: Double extension not properly handled
                if ($this->validateExtension($filename)) {
                    
                    // VULNERABILITY 17: Insecure file permissions
                    if (move_uploaded_file($file["tmp_name"], $target_file)) {
                        chmod($target_file, 0777);  // VULNERABILITY 18: Excessive permissions
                        
                        // VULNERABILITY 19: Information disclosure
                        return "Success! File uploaded to: " . $target_file;
                    }
                }
            }
        }
        
        return "Upload failed.";
    }
}

// VULNERABILITY 20: No session handling or authentication
if (isset($_POST["submit"])) {
    $uploader = new FileUploadHandler();
    echo $uploader->handleUpload();
}

// VULNERABILITY 21: XSS in error messages
if (isset($_GET['error'])) {
    echo $_GET['error'];
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Advanced Vulnerable File Upload</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .upload-form { border: 1px solid #ccc; padding: 20px; max-width: 500px; }
    </style>s
</head>
<body>
    <div class="upload-form">
        <h2>Advanced Vulnerable File Upload Form</h2>
        <!-- VULNERABILITY 22: Form action vulnerable to CSRF -->
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post" enctype="multipart/form-data">
            <!-- VULNERABILITY 23: No CSRF token -->
            <input type="file" name="fileToUpload" id="fileToUpload">
            <input type="submit" value="Upload File" name="submit">
        </form>
    </div>
    
    <?php
    // VULNERABILITY 24: Directory listing enabled
    if (isset($_GET['list'])) {
        $files = scandir($uploader->target_dir);
        echo "<pre>";
        print_r($files);
        echo "</pre>";
    }
    ?>
</body>
</html>
