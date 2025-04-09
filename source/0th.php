<?php
// src/Auth.php

class Auth {
    private $db;
    private $config;
    
    public function __construct($db, $config) {
        $this->db = $db;
        $this->config = $config;
    }
    
    /**
     * Authenticate a user with username/email and password
     * 
     * @param string $username Username or email
     * @param string $password Plain text password
     * @return array|false User data if authenticated, false otherwise
     */
    public function authenticate($username, $password) {
        // Check if input is email or username
        $field = filter_var($username, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';
        
        // Prepare query
        $stmt = $this->db->prepare("SELECT * FROM users WHERE $field = ? AND is_active = 1");
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            $this->logFailedAttempt($username);
            return false;
        }
        
        $user = $result->fetch_assoc();
        
        // Verify password
        if (!password_verify($password, $user['password_hash'])) {
            $this->logFailedAttempt($username, $user['id']);
            return false;
        }
        
        // Check if TOTP verification is required
        if ($user['totp_enabled']) {
            return ['user_id' => $user['id'], 'requires_totp' => true];
        }
        
        // Create session
        $token = $this->createSession($user['id']);
        
        $this->logSuccessfulLogin($user['id']);
        
        return [
            'user' => $user,
            'token' => $token
        ];
    }
    
    /**
     * Create a new session for a user
     * 
     * @param int $userId User ID
     * @return string JWT token
     */
    public function createSession($userId) {
        // Generate a random token
        $jwtPayload = [
            'sub' => $userId,
            'iat' => time(),
            'exp' => time() + $this->config['token_lifetime'],
            'jti' => bin2hex(random_bytes(16))
        ];
        
        // Create JWT token
        $token = $this->generateJwt($jwtPayload);
        
        // Store session in database
        $stmt = $this->db->prepare("INSERT INTO sessions (user_id, token, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, FROM_UNIXTIME(?))");
        $ip = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        $expiresAt = $jwtPayload['exp'];
        $stmt->bind_param('isssi', $userId, $jwtPayload['jti'], $ip, $userAgent, $expiresAt);
        $stmt->execute();
        
        return $token;
    }
    
    /**
     * Validate a token and return user data
     * 
     * @param string $token JWT token
     * @return array|false User data if valid, false otherwise
     */
    public function validateToken($token) {
        try {
            // Decode JWT
            $payload = $this->decodeJwt($token);
            
            // Check if token exists in database
            $stmt = $this->db->prepare("SELECT s.*, u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > NOW()");
            $stmt->bind_param('s', $payload['jti']);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                return false;
            }
            
            $sessionData = $result->fetch_assoc();
            
            // Check if user is still active
            if (!$sessionData['is_active']) {
                return false;
            }
            
            return [
                'user_id' => $sessionData['user_id'],
                'username' => $sessionData['username'],
                'email' => $sessionData['email'],
                'is_admin' => $sessionData['is_admin']
            ];
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Set authentication cookie
     * 
     * @param string $token JWT token
     * @return bool Success
     */
    public function setAuthCookie($token) {
        $cookieName = $this->config['cookie_name'];
        $domain = $this->config['cookie_domain'];
        $secure = $this->config['cookie_secure'];
        $httpOnly = true;
        $sameSite = 'Lax';  // Allows the cookie to be sent when navigating to your site
        $expires = time() + $this->config['token_lifetime'];
        
        $cookieOptions = [
            'expires' => $expires,
            'path' => '/',
            'domain' => $domain,
            'secure' => $secure,
            'httponly' => $httpOnly,
            'samesite' => $sameSite
        ];
        
        return setcookie($cookieName, $token, $cookieOptions);
    }
    
    /**
     * Logout user by invalidating session
     * 
     * @param string $token JWT token
     * @return bool Success
     */
    public function logout($token) {
        try {
            $payload = $this->decodeJwt($token);
            
            // Delete session from database
            $stmt = $this->db->prepare("DELETE FROM sessions WHERE token = ?");
            $stmt->bind_param('s', $payload['jti']);
            $result = $stmt->execute();
            
            // Clear cookie
            $this->clearAuthCookie();
            
            return $result;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Clear authentication cookie
     * 
     * @return bool Success
     */
    public function clearAuthCookie() {
        $cookieName = $this->config['cookie_name'];
        $domain = $this->config['cookie_domain'];
        
        return setcookie($cookieName, '', [
            'expires' => time() - 3600,
            'path' => '/',
            'domain' => $domain,
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }
    
    // JWT helper methods
    private function generateJwt($payload) {
        // In a real implementation, use a proper JWT library
        $header = json_encode(['alg' => 'HS256', 'typ' => 'JWT']);
        $payload = json_encode($payload);
        
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        
        $signature = hash_hmac('sha256', 
            $base64UrlHeader . "." . $base64UrlPayload, 
            $this->config['jwt_secret'], 
            true
        );
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        
        return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    }
    
    private function decodeJwt($jwt) {
        // In a real implementation, use a proper JWT library
        list($headerB64, $payloadB64, $signatureB64) = explode(".", $jwt);
        
        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $payloadB64)), true);
        
        if ($payload['exp'] < time()) {
            throw new Exception("Token expired");
        }
        
        return $payload;
    }
    
    private function logFailedAttempt($username, $userId = null) {
        $stmt = $this->db->prepare("INSERT INTO logs (user_id, action, ip_address, user_agent, details) VALUES (?, 'failed_login', ?, ?, ?)");
        $ip = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        $details = "Failed login attempt for username: $username";
        $stmt->bind_param('isss', $userId, $ip, $userAgent, $details);
        $stmt->execute();
    }
    
    private function logSuccessfulLogin($userId) {
        $stmt = $this->db->prepare("INSERT INTO logs (user_id, action, ip_address, user_agent) VALUES (?, 'successful_login', ?, ?)");
        $ip = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        $stmt->bind_param('iss', $userId, $ip, $userAgent);
        $stmt->execute();
    }
}