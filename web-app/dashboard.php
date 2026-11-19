<?php
session_start();
date_default_timezone_set('Africa/Nairobi');
require_once __DIR__ . '/../db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// Refresh user role from DB so role promotions take effect immediately
$roleStmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
$roleStmt->execute([$_SESSION['user_id']]);
$currentRole = $roleStmt->fetchColumn() ?: 'student';
$_SESSION['role'] = $currentRole;

$isStaff = in_array($currentRole, ['officer', 'admin'], true);
$ipBin = @inet_pton($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');

$success = '';
$error = '';

// 1. Handle New Incident Submission (Available to all authenticated users)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['report_incident'])) {
    $category_id = (int)$_POST['category_id'];
    $title = trim($_POST['subject']);
    $description = trim($_POST['description']);
    $location = trim($_POST['location'] ?? '');
    $occurred_raw = trim($_POST['occurred_at'] ?? '');
    $occurred_at = $occurred_raw ? date('Y-m-d H:i:s', strtotime($occurred_raw)) : date('Y-m-d H:i:s');
    $is_anonymous = isset($_POST['is_anonymous']) ? 1 : 0;

    $allowedPriorities = ['low', 'medium', 'high', 'critical'];
    $priority = in_array($_POST['priority'], $allowedPriorities, true) ? $_POST['priority'] : 'medium';

    // Generate Cryptographic Token + SHA-256 Binary Hash + 4-char Hint
    $token = 'INC-' . strtoupper(bin2hex(random_bytes(4)));
    $tokenHash = hash('sha256', $token, true);
    $tokenHint = substr($token, -4);

    try {
        $stmt = $pdo->prepare("
            INSERT INTO incidents 
            (tracking_token_hash, token_hint, reporter_id, tracking_token, is_anonymous, category_id, title, description, location, occurred_at, priority, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
        ");
        $stmt->execute([
            $tokenHash,
            $tokenHint,
            $_SESSION['user_id'],
            $token,
            $is_anonymous,
            $category_id,
            $title,
            $description,
            $location ?: null,
            $occurred_at,
            $priority
        ]);

        $newIncidentId = $pdo->lastInsertId();

        // Log to audit_log
        $log = $pdo->prepare("INSERT INTO audit_log (user_id, action, incident_id, ip_address, details) VALUES (?, 'INCIDENT_CREATED', ?, ?, ?)");
        $log->execute([$_SESSION['user_id'], $newIncidentId, $ipBin, "Filed {$priority} incident ({$token})"]);

        $success = "Incident filed successfully. Your Tracking Token is: <strong>$token</strong>";
    } catch (PDOException $e) {
        $error = "Submission error: " . $e->getMessage();
    }
}

// 2. Handle Officer / Admin Status Update (Server-Side RBAC Enforced!)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_status'])) {
    if (!$isStaff) {
        $error = "Access Denied: Only Security Officers or Admins can triage incidents.";
    } else {
        $incId = (int)$_POST['incident_id'];
        $newStatus = $_POST['new_status'];
        $note = trim($_POST['triage_note'] ?? '');
        $allowedStatuses = ['open', 'in_review', 'in_progress', 'resolved', 'closed'];

        if (in_array($newStatus, $allowedStatuses, true)) {
            try {
                $closedAt = in_array($newStatus, ['resolved', 'closed'], true) ? date('Y-m-d H:i:s') : null;
                $upd = $pdo->prepare("UPDATE incidents SET status = ?, assigned_to = ?, closed_at = COALESCE(?, closed_at) WHERE id = ?");
                $upd->execute([$newStatus, $_SESSION['user_id'], $closedAt, $incId]);

                $detailStr = "Status changed to '{$newStatus}'" . ($note !== '' ? " — Note: " . substr($note, 0, 180) : "");
                $log = $pdo->prepare("INSERT INTO audit_log (user_id, action, incident_id, ip_address, details) VALUES (?, 'STATUS_UPDATED', ?, ?, ?)");
                $log->execute([$_SESSION['user_id'], $incId, $ipBin, $detailStr]);

                $success = "Incident #{$incId} updated to <strong>" . htmlspecialchars($newStatus) . "</strong> and recorded in the audit log.";
            } catch (PDOException $e) {
                $error = "Update error: " . $e->getMessage();
            }
        }
    }
}

// Fetch categories
$categories = [];
try {
    $categories = $pdo->query("SELECT id, name FROM categories ORDER BY name ASC")->fetchAll();
} catch (Exception $e) {}

// Fetch current user's own incidents
$myIncidents = [];
try {
    $stmt = $pdo->prepare("SELECT i.*, c.name AS category_name FROM incidents i LEFT JOIN categories c ON i.category_id = c.id WHERE i.reporter_id = ? ORDER BY i.created_at DESC");
    $stmt->execute([$_SESSION['user_id']]);
    $myIncidents = $stmt->fetchAll();
} catch (Exception $e) {}

// Fetch ALL incidents & Audit Log if Officer/Admin
$allIncidents = [];
$auditLogs = [];
if ($isStaff) {
    try {
        $allIncidents = $pdo->query("
            SELECT i.*, c.name AS category_name, u.full_name AS reporter_name 
            FROM incidents i 
            LEFT JOIN categories c ON i.category_id = c.id 
            LEFT JOIN users u ON i.reporter_id = u.id 
            ORDER BY i.created_at DESC
        ")->fetchAll();

        $auditLogs = $pdo->query("
            SELECT a.*, u.full_name AS actor_name, u.role AS actor_role, INET6_NTOA(a.ip_address) AS ip_str
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.created_at DESC
            LIMIT 25
        ")->fetchAll();
    } catch (Exception $e) {}
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard — Incident Portal</title>
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
      --accent-light: #eaf1ed;
      --badge: #2b593f;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg); color: var(--ink);
      font-family: 'Inter', -apple-system, sans-serif; font-size: 14px; line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }
    header {
      border-bottom: 1px solid var(--line); padding: 18px 40px;
      display: flex; justify-content: space-between; align-items: center; background: var(--bg);
    }
    .brand {
      font-size: 14px; font-weight: 600; letter-spacing: -0.01em;
      text-transform: uppercase; text-decoration: none; color: var(--ink);
    }
    .header-right { display: flex; align-items: center; gap: 16px; }
    .role-pill {
      font-family: 'JetBrains Mono', monospace; font-size: 11px; text-transform: uppercase;
      padding: 4px 10px; border-radius: 999px;
      background: <?= $isStaff ? '#fef3c7' : 'var(--accent-light)' ?>;
      color: <?= $isStaff ? '#92400e' : 'var(--badge)' ?>;
    }
    .user-tag { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--muted); }
    .btn-logout {
      font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--ink);
      text-decoration: none; border: 1px solid var(--line-dark); padding: 6px 14px; border-radius: 2px;
    }
    .btn-logout:hover { background: var(--ink); color: var(--bg); }
    main { max-width: 1100px; margin: 0 auto; padding: 45px 24px 80px; }
    .card {
      background: var(--surface); border: 1px solid var(--line);
      border-radius: 2px; padding: 32px; margin-bottom: 32px;
    }
    .card h2 {
      font-family: 'Instrument Serif', Georgia, serif;
      font-size: 28px; font-weight: 400; margin-bottom: 6px;
    }
    .card p.desc { color: var(--muted); font-size: 13px; margin-bottom: 20px; }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
    label {
      display: block; font-family: 'JetBrains Mono', monospace; font-size: 11px;
      text-transform: uppercase; color: var(--muted); margin-bottom: 6px;
    }
    input, select, textarea {
      width: 100%; padding: 10px 12px; margin-bottom: 16px; border: 1px solid var(--line);
      background: var(--bg); color: var(--ink); font-family: inherit; font-size: 14px; border-radius: 2px;
    }
    input:focus, select:focus, textarea:focus { outline: none; border-color: var(--line-dark); }
    .checkbox-row { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; font-size: 13px; color: var(--muted); }
    .checkbox-row input { width: auto; margin: 0; }
    button {
      padding: 11px 22px; background: var(--ink); color: var(--bg);
      border: none; border-radius: 2px; font-weight: 500; font-size: 13px; cursor: pointer;
    }
    button:hover { background: #333; }
    button.btn-sm { padding: 6px 12px; font-size: 12px; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th {
      text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 11px;
      text-transform: uppercase; color: var(--muted); padding: 10px 8px; border-bottom: 1px solid var(--line);
    }
    td { padding: 12px 8px; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: top; }
    .token-badge {
      font-family: 'JetBrains Mono', monospace; font-size: 11px;
      background: var(--accent-light); color: var(--badge); padding: 3px 8px; border-radius: 2px;
    }
    .mono { font-family: 'JetBrains Mono', monospace; font-size: 11px; }
    .msg-success {
      background: var(--accent-light); color: var(--badge); border: 1px solid #cce0d4;
      padding: 12px; font-size: 13px; margin-bottom: 18px;
    }
    .msg-error {
      background: #fdf2f2; color: #991b1b; border: 1px solid #fecaca;
      padding: 12px; font-size: 13px; margin-bottom: 18px;
    }
    .triage-form { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
    .triage-form select, .triage-form input { margin-bottom: 0; padding: 6px 8px; font-size: 12px; width: auto; }
    .triage-form input { min-width: 150px; }
  </style>
</head>
<body>

  <header>
    <a href="https://trigun.me" class="brand">Incident Portal</a>
    <div class="header-right">
      <span class="role-pill">Role: <?= htmlspecialchars($currentRole) ?></span>
      <span class="user-tag"><?= htmlspecialchars($_SESSION['fullname']) ?></span>
      <a href="logout.php" class="btn-logout">Logout ↳</a>
    </div>
  </header>

  <main>
    <?php if ($success): ?><div class="msg-success"><?= $success ?></div><?php endif; ?>
    <?php if ($error): ?><div class="msg-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($isStaff): ?>
    <!-- PRIVILEGED OFFICER / ADMIN TRIAGE QUEUE -->
    <div class="card" style="border-left: 3px solid #92400e;">
      <h2>Security Officer Triage Queue</h2>
      <p class="desc">Privileged RBAC View: Review all campus incident reports, update resolution statuses, and log actions.</p>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Token</th>
              <th>Reporter</th>
              <th>Title & Location</th>
              <th>Priority</th>
              <th>Current Status</th>
              <th>Triage Action</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($allIncidents as $inc): ?>
              <tr>
                <td><span class="token-badge"><?= htmlspecialchars($inc['tracking_token'] ?? ('#' . $inc['id'])) ?></span></td>
                <td><?= $inc['is_anonymous'] ? '<em style="color:var(--muted);">Anonymous</em>' : htmlspecialchars($inc['reporter_name'] ?? 'Unknown') ?></td>
                <td>
                  <strong><?= htmlspecialchars($inc['title']) ?></strong><br>
                  <span style="color:var(--muted); font-size:12px;"><?= htmlspecialchars($inc['category_name'] ?? 'General') ?> · <?= htmlspecialchars($inc['location'] ?: 'Campus') ?></span>
                </td>
                <td style="text-transform: capitalize;"><?= htmlspecialchars($inc['priority']) ?></td>
                <td class="mono" style="text-transform: uppercase; font-weight:600;"><?= htmlspecialchars($inc['status']) ?></td>
                <td>
                  <form method="POST" class="triage-form">
                    <input type="hidden" name="incident_id" value="<?= $inc['id'] ?>">
                    <select name="new_status">
                      <?php foreach (['open', 'in_review', 'in_progress', 'resolved', 'closed'] as $st): ?>
                        <option value="<?= $st ?>" <?= $inc['status'] === $st ? 'selected' : '' ?>><?= $st ?></option>
                      <?php endforeach; ?>
                    </select>
                    <input type="text" name="triage_note" placeholder="Audit note (optional)">
                    <button type="submit" name="update_status" class="btn-sm">Update</button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php endif; ?>

    <!-- SUBMIT INCIDENT FORM -->
    <div class="card">
      <h2>File Incident Report</h2>
      <p class="desc">Submit a campus security or technical incident with strict HTML5 validation.</p>

      <form method="POST">
        <div class="form-grid">
          <div>
            <label>Incident Category</label>
            <select name="category_id" required>
              <?php foreach ($categories as $cat): ?>
                <option value="<?= $cat['id'] ?>"><?= htmlspecialchars($cat['name']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div>
            <label>Priority Tier</label>
            <select name="priority" required>
              <option value="low">Low</option>
              <option value="medium" selected>Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>

        <label>Title / Subject (Min 5 characters)</label>
        <input type="text" name="subject" required minlength="5" maxlength="150" placeholder="e.g. Received spoofed password reset email">

        <div class="form-grid">
          <div>
            <label>Campus Location (Optional)</label>
            <input type="text" name="location" maxlength="150" placeholder="e.g. Phase II Computer Lab / Student Mail">
          </div>
          <div>
            <label>Date & Time Occurred</label>
            <input type="datetime-local" name="occurred_at" required value="<?= date('Y-m-d\TH:i') ?>">
          </div>
        </div>

        <label>Incident Details (Min 20 characters)</label>
        <textarea name="description" rows="4" required minlength="20" maxlength="1000" placeholder="Provide context, error codes, or sender details..."></textarea>

        <div class="checkbox-row">
          <input type="checkbox" id="is_anonymous" name="is_anonymous" value="1">
          <label for="is_anonymous" style="margin:0; text-transform:none; font-family:inherit; font-size:13px;">Submit anonymously (hides your name from Officer Triage Queue)</label>
        </div>

        <button type="submit" name="report_incident">Submit Incident ↳</button>
      </form>
    </div>

    <!-- MY REPORTED INCIDENTS -->
    <div class="card">
      <h2>My Reported Incidents</h2>
      <p class="desc">Track your submitted tickets and query their status via <a href="https://api.trigun.me" style="color:var(--ink);">api.trigun.me</a>.</p>

      <?php if (empty($myIncidents)): ?>
        <p style="color: var(--muted); font-size: 13px;">You have not filed any incidents yet.</p>
      <?php else: ?>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Tracking Token</th>
                <th>Title</th>
                <th>Category</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Occurred</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($myIncidents as $inc): ?>
                <tr>
                  <td><span class="token-badge"><?= htmlspecialchars($inc['tracking_token'] ?? 'N/A') ?></span></td>
                  <td><?= htmlspecialchars($inc['title']) ?></td>
                  <td><?= htmlspecialchars($inc['category_name'] ?? 'General') ?></td>
                  <td style="text-transform: capitalize;"><?= htmlspecialchars($inc['priority']) ?></td>
                  <td class="mono" style="text-transform: uppercase; font-weight: 600;"><?= htmlspecialchars($inc['status']) ?></td>
                  <td class="mono" style="color:var(--muted);"><?= htmlspecialchars($inc['occurred_at']) ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </div>

    <?php if ($isStaff): ?>
    <!-- SECURITY AUDIT TRAIL (OFFICER / ADMIN ONLY) -->
    <div class="card">
      <h2>Security Audit Trail</h2>
      <p class="desc">Immutable log of authentications, failed attempts, incident submissions, and triage changes.</p>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Timestamp (EAT)</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Incident</th>
              <th>IP Address</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($auditLogs as $log): ?>
              <tr>
                <td class="mono" style="color:var(--muted);"><?= htmlspecialchars($log['created_at']) ?></td>
                <td><?= htmlspecialchars($log['actor_name'] ?? 'Unknown/Guest') ?> <span class="mono" style="color:var(--muted);">(<?= htmlspecialchars($log['actor_role'] ?? '-') ?>)</span></td>
                <td class="mono" style="font-weight:600;"><?= htmlspecialchars($log['action']) ?></td>
                <td class="mono"><?= $log['incident_id'] ? '#' . $log['incident_id'] : '-' ?></td>
                <td class="mono"><?= htmlspecialchars($log['ip_str'] ?? '-') ?></td>
                <td><?= htmlspecialchars($log['details'] ?? '') ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php endif; ?>

  </main>

</body>
</html>
