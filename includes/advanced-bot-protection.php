
<?php
// advanced-bot-protection.php

class AdvancedBotProtection {
    private $jsToken;
    private $ip;
    private $userAgent;
    private $requestTime;
    
    public function __construct() {
        $this->jsToken = $_SERVER['HTTP_X_JS_TOKEN'] ?? $_POST['js_token'] ?? '';
        $this->ip = $this->getRealIP();
        $this->userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->requestTime = $_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true);
    }
    
    private function getRealIP() {
        $ip = $_SERVER['REMOTE_ADDR'];
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }
    
    private function validateJSToken() {
        if (empty($this->jsToken) || $this->jsToken === 'invalid') {
            return false;
        }
        
        try {
            $data = json_decode(base64_decode($this->jsToken), true);
            
            // Check token age (max 10 seconds old)
            if (time() - ($data['t'] / 1000) > 10) {
                return false;
            }
            
            // Check complexity score
            if ($data['c'] < 0.5 && $data['m'] < 3) {
                return false;
            }
            
            // Verify user agent matches
            if ($data['u'] !== $this->userAgent) {
                return false;
            }
            
            return true;
        } catch (Exception $e) {
            return false;
        }
    }
    
    private function checkIPReputation() {
        // Check against local IP blacklist
        $blacklist = file(__DIR__ . '/ip-blacklist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (in_array($this->ip, $blacklist)) {
            return false;
        }
        
        // Optionally: Query external IP reputation service
        // $this->queryIPReputationAPI();
        
        return true;
    }
    
    private function checkRequestPattern() {
        // Check for common bot patterns
        $botPatterns = [
            '/http:\/\//i', '/https:\/\//i', // URLs in headers
            '/select.*from/i', '/union.*select/i', // SQLi patterns
            '/<\?php/i', '/eval\(/i', '/base64_decode\(/i' // PHP injection
        ];
        
        foreach ($_SERVER as $key => $value) {
            foreach ($botPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    private function logBotAttempt() {
        $logEntry = sprintf(
            "[%s] Bot attempt from %s - UA: %s - Token: %s\n",
            date('Y-m-d H:i:s'),
            $this->ip,
            $this->userAgent,
            $this->jsToken
        );
        
        file_put_contents(__DIR__ . '/bot-attempts.log', $logEntry, FILE_APPEND);
        
        // Add to temporary blacklist if multiple attempts
        $this->updateIPBlacklist();
    }
    
    private function updateIPBlacklist() {
        $file = DIR . '/ip-blacklist.txt';
        $attempts = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        // Count recent attempts from this IP
        $count = 0;
        $log = file(__DIR__ . '/bot-attempts.log');
        foreach ($log as $line) {
            if (strpos($line, $this->ip) !== false) {
                $count++;
            }
        }
        
        // Add to blacklist if more than 5 attempts
        if ($count > 5 && !in_array($this->ip, $attempts)) {
            file_put_contents($file, $this->ip . "\n", FILE_APPEND);
        }
    }
    
    public function isBot() {
        // Check if JS validation failed
        if (!$this->validateJSToken()) {
            $this->logBotAttempt();
            return true;
        }
        
        // Check IP reputation
        if (!$this->checkIPReputation()) {
            $this->logBotAttempt();
            return true;
        }

// Check request patterns
        if (!$this->checkRequestPattern()) {
            $this->logBotAttempt();
            return true;
        }
        
        return false;
    }
    
    public function challengeBot() {
        // Serve a CAPTCHA or block completely
        http_response_code(403);
        die('Access denied. Please contact support if you believe this is an error.');
    }
}

// Usage:
$botProtection = new AdvancedBotProtection();
if ($botProtection->isBot()) {
    $botProtection->challengeBot();
}
?>