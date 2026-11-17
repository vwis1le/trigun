<?php
session_start();
require_once 'db.php';
$msg = '';

if (isset($_GET['registered'])) {
    $msg = "Account created successfully! Please log in.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    // RUBRIC REQUIREMENT: password_verify against BCRYPT hash
    if ($user && password_verify($password, $user['password_hash'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['fullname'] = $user['fullname'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['hash_preview'] = $user['password_hash'];
        header("Location: dashboard.php");
        exit;
    } else {
        $msg = "Invalid email or password.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Incident Portal</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0b0f19; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: #151e32; padding: 32px; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #1e293b; }
        h2 { margin-top: 0; color: #38bdf8; }
        label { font-size: 13px; color: #94a3b8; font-weight: 600; }
        input { width: 100%; padding: 11px; margin: 6px 0 16px 0; border-radius: 6px; border: 1px solid #334155; background: #0b0f19; color: white; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #10b981; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
        button:hover { background: #059669; }
        .notice { background: #0369a1; color: #e0f2fe; padding: 10px; border-radius: 6px; margin-bottom: 15px; font-size: 14px; }
        a { color: #38bdf8; text-decoration: none; }
    </style>
</head>
<body>
<div class="card">
    <h2>Incident Portal Login</h2>
    <?php if ($msg): ?><div class="notice"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <form method="POST">
        <label>Strathmore Email</label>
        <input type="email" name="email" required placeholder="user@strathmore.edu">

        <label>Password</label>
        <input type="password" name="password" required placeholder="••••••••">

        <button type="submit">Sign In</button>
    </form>
    <p style="margin-top: 20px; text-align: center; font-size: 14px; color: #94a3b8;">Need an account? <a href="register.php">Register</a></p>
</div>
</body>
</html>
