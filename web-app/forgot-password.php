<?php
require_once __DIR__ . '/../session_init.php';
require_once __DIR__ . '/../db.php';
$msg = '';
$step = 1;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['find_account'])) {
        $email = trim($_POST['email']);
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user) {
            $_SESSION['reset_email'] = $email;
            $step = 2;
        } else {
            $msg = "No account found matching this email.";
        }
    } elseif (isset($_POST['update_password'])) {
        $email = $_SESSION['reset_email'] ?? '';
        $new_password = $_POST['new_password'];

        if (!$email) {
            header("Location: forgot-password.php");
            exit;
        }

        if (strlen($new_password) < 8) {
            $msg = "Password must be at least 8 characters.";
            $step = 2;
        } else {
            $hashed = password_hash($new_password, PASSWORD_BCRYPT);
            $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE email = ?");
            $stmt->execute([$hashed, $email]);

            unset($_SESSION['reset_email']);
            header("Location: login.php?reset=1");
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password — Incident Portal</title>
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
      background-color: var(--bg);
      color: var(--ink);
      font-family: 'Inter', -apple-system, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 20px;
    }

    .auth-box {
      width: 100%;
      max-width: 400px;
      background: var(--surface);
      border: 1px solid var(--line);
      padding: 40px 36px;
    }

    h1 {
      font-family: 'Instrument Serif', Georgia, serif;
      font-size: 32px;
      font-weight: 400;
      letter-spacing: -0.01em;
      margin-bottom: 6px;
    }

    p.sub {
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 24px;
    }

    label {
      display: block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 6px;
    }

    input {
      width: 100%;
      padding: 10px 12px;
      margin-bottom: 18px;
      border: 1px solid var(--line);
      background: var(--bg);
      color: var(--ink);
      font-family: inherit;
      font-size: 14px;
      border-radius: 2px;
    }
    input:focus { outline: none; border-color: var(--line-dark); }

    button {
      width: 100%;
      padding: 12px;
      background: var(--ink);
      color: var(--bg);
      border: none;
      font-weight: 500;
      font-size: 14px;
      cursor: pointer;
      border-radius: 2px;
      margin-top: 6px;
    }
    button:hover { background: #333; }

    .msg {
      background: #fdf2f2;
      color: #991b1b;
      border: 1px solid #fecaca;
      padding: 10px 12px;
      font-size: 13px;
      margin-bottom: 18px;
    }

    .footer-nav {
      margin-top: 24px;
      padding-top: 18px;
      border-top: 1px solid var(--line);
      text-align: center;
      font-size: 12px;
    }
    .footer-nav a { color: var(--muted); text-decoration: none; }
    .footer-nav a:hover { color: var(--ink); text-decoration: underline; }
  </style>
</head>
<body>

  <div class="auth-box">
    <h1>Reset Password</h1>
    <p class="sub">Account Recovery</p>

    <?php if ($msg): ?><div class="msg"><?= htmlspecialchars($msg) ?></div><?php endif; ?>

    <?php if ($step === 1): ?>
      <form method="POST">
        <label>Student Email</label>
        <input type="email" name="email" required placeholder="name@strathmore.edu">
        <button type="submit" name="find_account">Find Account ↳</button>
      </form>
    <?php else: ?>
      <form method="POST">
        <label>New Password (Min 8 chars, 1 Uppercase, 1 Number)</label>
        <input type="password" name="new_password" required 
               pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" 
               title="Must contain at least 8 characters, including 1 uppercase letter and 1 number"
               placeholder="••••••••">
        <button type="submit" name="update_password">Save New Password ↳</button>
      </form>
    <?php endif; ?>

    <div class="footer-nav">
      <a href="login.php">Back to Sign In →</a>
    </div>
  </div>

</body>
</html>
