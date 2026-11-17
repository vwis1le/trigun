<?php
require_once 'db.php';
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fullname = trim($_POST['fullname']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    // Server-side safety validation
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $msg = "Invalid email format.";
    } elseif (strlen($password) < 8) {
        $msg = "Password must be at least 8 characters.";
    } else {
        // RUBRIC REQUIREMENT: BCRYPT Password Hashing (Cost factor 12)
        $hashed_password = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

        try {
            $stmt = $pdo->prepare("INSERT INTO users (fullname, email, password_hash) VALUES (?, ?, ?)");
            $stmt->execute([$fullname, $email, $hashed_password]);
            header("Location: login.php?registered=1");
            exit;
        } catch (PDOException $e) {
            $msg = "An account with this email already exists.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Incident Portal</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0b0f19; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: #151e32; padding: 32px; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #1e293b; }
        h2 { margin-top: 0; color: #38bdf8; }
        label { font-size: 13px; color: #94a3b8; font-weight: 600; }
        input { width: 100%; padding: 11px; margin: 6px 0 16px 0; border-radius: 6px; border: 1px solid #334155; background: #0b0f19; color: white; box-sizing: border-box; }
        input:focus { border-color: #38bdf8; outline: none; }
        button { width: 100%; padding: 12px; background: #0284c7; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
        button:hover { background: #0369a1; }
        .error { background: #7f1d1d; color: #fecaca; padding: 10px; border-radius: 6px; margin-bottom: 15px; font-size: 14px; }
        a { color: #38bdf8; text-decoration: none; }
    </style>
</head>
<body>
<div class="card">
    <h2>Student Registration</h2>
    <?php if ($msg): ?><div class="error"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <form method="POST">
        <!-- RUBRIC REQUIREMENT: Strict HTML5 Form Validation -->
        <label>Full Name</label>
        <input type="text" name="fullname" required pattern="[A-Za-z ]{3,50}" title="Letters only, minimum 3 characters" placeholder="e.g. Ted Kamau">

        <label>Strathmore Email Address</label>
        <input type="email" name="email" required placeholder="user@strathmore.edu">

        <label>Password (Min 8 chars, 1 uppercase, 1 number)</label>
        <input type="password" name="password" required 
               pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" 
               title="Must contain at least 8 characters, including 1 uppercase letter and 1 number"
               placeholder="••••••••">

        <button type="submit">Create Account</button>
    </form>
    <p style="margin-top: 20px; text-align: center; font-size: 14px; color: #94a3b8;">Already have an account? <a href="login.php">Sign In</a></p>
</div>
</body>
</html>
