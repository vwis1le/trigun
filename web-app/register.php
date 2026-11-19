<?php
require_once __DIR__ . '/../db.php';
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name = trim($_POST['fullname']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $msg = "Invalid email format.";
    } elseif (strlen($password) < 8) {
        $msg = "Password must be at least 8 characters.";
    } else {
        $hashed = password_hash($password, PASSWORD_BCRYPT);
        try {
            $stmt = $pdo->prepare("INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, 'student')");
            $stmt->execute([$full_name, $email, $hashed]);
            header("Location: login.php?registered=1");
            exit;
        } catch (PDOException $e) {
            if ($e->errorInfo[1] == 1062) {
                $msg = "An account with this email already exists.";
            } else {
                $msg = "Database Error: " . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register — Incident Portal</title>
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
      max-width: 420px;
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
    <h1>Create Account</h1>

    <?php if ($msg): ?><div class="msg"><?= htmlspecialchars($msg) ?></div><?php endif; ?>

    <form method="POST">
      <label>Full Name</label>
      <input type="text" name="fullname" required pattern="[A-Za-z ]{3,50}" title="Letters only, minimum 3 characters" placeholder="e.g. Ted Kamau">

      <label>Your Email</label>
      <input type="email" name="email" required placeholder="name@strathmore.edu">

      <label>Password (Min 8 chars, 1 Uppercase, 1 Number)</label>
      <input type="password" name="password" required 
             pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" 
             title="Must contain at least 8 characters, including 1 uppercase letter and 1 number"
             placeholder="••••••••">

      <button type="submit">Register Account ↳</button>
    </form>

    <div class="footer-nav">
      Already registered? <a href="login.php">Sign In →</a>
    </div>
  </div>

</body>
</html>
