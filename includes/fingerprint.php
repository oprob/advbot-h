<?php
class SessionFingerprint {
    public function __construct() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(['cookie_httponly' => true, 'cookie_secure' => true]);
        }
    }

    public function validate(): bool {
        return hash_equals($this->generate(), $_SESSION['fingerprint'] ?? '');
    }

    public function getClientIP(): string {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] 
            ?? $_SERVER['HTTP_X_FORWARDED_FOR'] 
            ?? $_SERVER['REMOTE_ADDR'] 
            ?? '0.0.0.0';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    public function getDeviceHash(): string {
        return hash('sha256', 
            ($_SERVER['HTTP_USER_AGENT'] ?? '') . 
            ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '') . 
            ($_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '') .
            ($_SERVER['HTTP_SEC_CH_UA'] ?? '')
        );
    }

    private function generate(): string {
        if (empty($_SESSION['fingerprint'])) {
            $_SESSION['fingerprint'] = hash('sha256', 
                $this->getClientIP() . 
                $this->getDeviceHash() . 
                bin2hex(random_bytes(16))
            );
        }
        return $_SESSION['fingerprint'];
    }
}