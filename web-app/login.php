<?php
require_once __DIR__ . '/../session_init.php';
date_default_timezone_set('Africa/Nairobi');
require_once __DIR__ . '/../db.php';
$msg = '';

if (isset($_GET['registered'])) {
    $msg = "Registration successful. Please sign in.";
}
if (isset($_GET['reset'])) {
    $msg = "Password reset successful. Please sign in.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $ipBin = @inet_pton($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['fullname'] = $user['full_name'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['role'] = $user['role'];

        try {
            $log = $pdo->prepare("INSERT INTO audit_log (user_id, action, incident_id, ip_address, details) VALUES (?, 'USER_LOGIN', NULL, ?, ?)");
            $log->execute([$user['id'], $ipBin, "Authenticated as role: " . $user['role']]);
        } catch (Exception $e) {}

        header("Location: dashboard.php");
        exit;
    } else {
        try {
            $log = $pdo->prepare("INSERT INTO audit_log (user_id, action, incident_id, ip_address, details) VALUES (?, 'LOGIN_FAILED', NULL, ?, ?)");
            $log->execute([$user ? $user['id'] : null, $ipBin, "Failed login attempt for: " . substr($email, 0, 100)]);
        } catch (Exception $e) {}

        $msg = "Invalid email or password.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — Incident Portal</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #faf8f5;
      --surface: #ffffff;
      --ink: #191816;
      --muted: #6e6b64;
      --line: #e6e2d8;
      --line-dark: #191816;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg); color: var(--ink);
      font-family: 'Inter', -apple-system, sans-serif; font-size: 14px; line-height: 1.6;
      display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px;
    }
    .auth-box {
      width: 100%; max-width: 400px; background: var(--surface);
      border: 1px solid var(--line); padding: 40px 36px;
    }
    h1 { font-family: 'Instrument Serif', Georgia, serif; font-size: 32px; font-weight: 400; margin-bottom: 6px; }
    p.sub { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
    label {
      display: block; font-family: 'JetBrains Mono', monospace; font-size: 11px;
      text-transform: uppercase; color: var(--muted); margin-bottom: 6px;
    }
    input {
      width: 100%; padding: 10px 12px; margin-bottom: 18px; border: 1px solid var(--line);
      background: var(--bg); color: var(--ink); font-family: inherit; font-size: 14px; border-radius: 2px;
    }
    input:focus { outline: none; border-color: var(--line-dark); }
    button {
      width: 100%; padding: 12px; background: var(--ink); color: var(--bg);
      border: none; font-weight: 500; font-size: 14px; cursor: pointer; border-radius: 2px; margin-top: 6px;
    }
    button:hover { background: #333; }
    .msg {
      background: #fdf2f2; color: #991b1b; border: 1px solid #fecaca;
      padding: 10px 12px; font-size: 13px; margin-bottom: 18px;
    }
    .footer-nav {
      margin-top: 24px; padding-top: 18px; border-top: 1px solid var(--line);
      display: flex; justify-content: space-between; font-size: 12px;
    }
    .footer-nav a { color: var(--muted); text-decoration: none; }
    .footer-nav a:hover { color: var(--ink); text-decoration: underline; }
  </style>
</head>
<body>
  <div class="auth-box">
    <h1>Sign In</h1>
    <p class="sub">Incident Response Management Portal</p>
    <?php if ($msg): ?><div class="msg"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <form method="POST">
      <label>Your Email</label>
      <input type="email" name="email" required placeholder="name@strathmore.edu">
      <label>Password</label>
      <input type="password" name="password" required placeholder="••••••••">
      <button type="submit">Sign In ↳</button>
    </form>
    <div class="footer-nav">
      <a href="register.php">Create Account →</a>
      <a href="forgot-password.php">Forgot Password?</a>
    </div>
  </div>
</body>
</html><?php
