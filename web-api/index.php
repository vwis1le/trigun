<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once '../web-app/db.php';

$token = isset($_GET['token']) ? trim($_GET['token']) : '';

// If no token provided, return live server telemetry & health
if (!$token) {
    echo json_encode([
        "system" => "Strathmore Incident & Telemetry API",
        "status" => "OPERATIONAL",
        "ssl_secured" => true,
        "ssl_provider" => "ZeroSSL",
        "server_load" => sys_getloadavg()[0],
        "server_time" => date('Y-m-d H:i:s'),
        "usage" => "Query token status using: ?token=INC-XXXX"
    ], JSON_PRETTY_PRINT);
    exit;
}

// Token Verification Query
$stmt = $pdo->prepare("SELECT tracking_token, category, subject, priority, status, created_at FROM incidents WHERE tracking_token = ?");
$stmt->execute([$token]);
$incident = $stmt->fetch();

if ($incident) {
    echo json_encode([
        "status" => "verified",
        "incident" => $incident,
        "verified_at" => date('c')
    ], JSON_PRETTY_PRINT);
} else {
    echo json_encode([
        "status" => "not_found",
        "message" => "Invalid Tracking Token: No record matches."
    ], JSON_PRETTY_PRINT);
}
?>
