<?php
date_default_timezone_set('Africa/Nairobi');
require_once __DIR__ . '/../db.php';

// 1. Handle Token Lookup API (?token=INC-XXXX)
if (isset($_GET['token']) && trim($_GET['token']) !== '') {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    $token = trim($_GET['token']);

    try {
        $stmt = $pdo->prepare("SELECT i.tracking_token, i.title, c.name AS category, i.priority, i.status, i.created_at FROM incidents i LEFT JOIN categories c ON i.category_id = c.id WHERE i.tracking_token = ?");
        $stmt->execute([$token]);
        $incident = $stmt->fetch();

        if ($incident) {
            echo json_encode([
                'status' => 'found',
                'incident' => $incident,
                'verified_over' => 'ZeroSSL TLS 1.3'
            ], JSON_PRETTY_PRINT);
        } else {
            http_response_code(404);
            echo json_encode([
                'status' => 'not_found',
                'message' => 'No incident record matches this tracking token.'
            ], JSON_PRETTY_PRINT);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
    exit;
}

// 2. Real-Time Live Database Endpoint (?live_db=1)
if (isset($_GET['live_db']) && $_GET['live_db'] === '1') {
    header('Content-Type: application/json');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    $response = [
        'timestamp' => date('H:i:s T'),
        'tables' => [],
        'users' => [],
        'incidents' => []
    ];

    try {
        // Fetch all tables and live row counts
        $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
        foreach ($tables as $tbl) {
            $count = (int)$pdo->query("SELECT COUNT(*) FROM `$tbl`")->fetchColumn();
            $response['tables'][] = ['name' => $tbl, 'rows' => $count];
        }

        // Fetch latest users (proving BCRYPT hashing)
        $response['users'] = $pdo->query(
            "SELECT id, full_name, email, role, password_hash FROM users ORDER BY id DESC LIMIT 15"
        )->fetchAll();

        // Fetch latest incidents
        $response['incidents'] = $pdo->query(
            "SELECT i.id, i.tracking_token, i.title, c.name AS category, i.priority, i.status, i.created_at 
             FROM incidents i 
             LEFT JOIN categories c ON i.category_id = c.id 
             ORDER BY i.id DESC LIMIT 15"
        )->fetchAll();
    } catch (Exception $e) {
        $response['error'] = $e->getMessage();
    }

    echo json_encode($response);
    exit;
}

// 3. Gather Live Server Telemetry
$load = sys_getloadavg();

$memTotalMB = 0; $memUsedMB = 0; $memPercent = 0;
if (is_readable('/proc/meminfo')) {
    $meminfo = file_get_contents('/proc/meminfo');
    preg_match('/MemTotal:\s+(\d+)/', $meminfo, $totalMatch);
    preg_match('/MemAvailable:\s+(\d+)/', $meminfo, $availMatch);
    $memTotalMB = isset($totalMatch[1]) ? round($totalMatch[1] / 1024) : 0;
    $memAvailMB = isset($availMatch[1]) ? round($availMatch[1] / 1024) : 0;
    $memUsedMB = $memTotalMB - $memAvailMB;
    $memPercent = $memTotalMB > 0 ? round(($memUsedMB / $memTotalMB) * 100, 1) : 0;
}

$diskTotalGB = round(disk_total_space('/') / 1073741824, 2);
$diskFreeGB = round(disk_free_space('/') / 1073741824, 2);
$diskUsedGB = round($diskTotalGB - $diskFreeGB, 2);
$diskPercent = $diskTotalGB > 0 ? round(($diskUsedGB / $diskTotalGB) * 100, 1) : 0;

$uptimeText = 'Unknown';
if (is_readable('/proc/uptime')) {
    $uptimeSec = (int)explode(' ', file_get_contents('/proc/uptime'))[0];
    $d = floor($uptimeSec / 86400);
    $h = floor(($uptimeSec % 86400) / 3600);
    $m = floor(($uptimeSec % 3600) / 60);
    $uptimeText = "{$d}d {$h}h {$m}m";
}

// 4. Parse ZeroSSL Certificate directly using OpenSSL
$certPath = '/etc/ssl/trigun/fullchain.crt';
$sslData = [
    'status' => 'Certificate File Unreadable',
    'issuer' => 'N/A',
    'sans' => 'N/A',
    'valid_from' => 'N/A',
    'valid_to' => 'N/A',
    'days_left' => 0
];
if (is_readable($certPath)) {
    $parsed = openssl_x509_parse(file_get_contents($certPath));
    if ($parsed) {
        $validTo = $parsed['validTo_time_t'];
        $validFrom = $parsed['validFrom_time_t'];
        $daysLeft = (int)floor(($validTo - time()) / 86400);
        $sslData = [
            'status' => $daysLeft > 0 ? 'Active & Valid' : 'Expired',
            'issuer' => $parsed['issuer']['O'] ?? ($parsed['issuer']['CN'] ?? 'ZeroSSL'),
            'common_name' => $parsed['subject']['CN'] ?? 'trigun.me',
            'sans' => str_replace('DNS:', '', $parsed['extensions']['subjectAltName'] ?? 'trigun.me'),
            'valid_from' => date('Y-m-d', $validFrom),
            'valid_to' => date('Y-m-d', $validTo),
            'days_left' => $daysLeft
        ];
    }
}

// 5. Live MySQL Status
$dbStatus = 'Disconnected';
$mysqlVersion = 'N/A';
$userCount = 0;
$incidentCount = 0;
try {
    $mysqlVersion = $pdo->query("SELECT VERSION()")->fetchColumn();
    $userCount = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    $incidentCount = (int)$pdo->query("SELECT COUNT(*) FROM incidents")->fetchColumn();
    $dbStatus = 'Connected (Healthy)';
} catch (Exception $e) {
    $dbStatus = 'Error: ' . $e->getMessage();
}

$telemetry = [
    'service' => 'Trigun Infrastructure & SSL Telemetry API',
    'timestamp_eat' => date('Y-m-d H:i:s T'),
    'compute' => [
        'os' => php_uname('s') . ' ' . php_uname('r'),
        'php_version' => phpversion(),
        'uptime' => $uptimeText,
        'cpu_load_avg' => ['1m' => $load[0], '5m' => $load[1], '15m' => $load[2]],
        'memory' => ['used_mb' => $memUsedMB, 'total_mb' => $memTotalMB, 'percent' => $memPercent],
        'disk' => ['used_gb' => $diskUsedGB, 'total_gb' => $diskTotalGB, 'percent' => $diskPercent]
    ],
    'ssl_certificate' => $sslData,
    'database' => [
        'status' => $dbStatus,
        'engine' => 'MySQL ' . $mysqlVersion,
        'total_users' => $userCount,
        'total_incidents' => $incidentCount
    ]
];

if (isset($_GET['format']) && $_GET['format'] === 'json') {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    echo json_encode($telemetry, JSON_PRETTY_PRINT);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Telemetry & Live Database — Incident Portal</title>
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
      --accent-light: #eaf1ed;
      --badge: #2b593f;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--ink);
      font-family: 'Inter', -apple-system, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }
    header {
      border-bottom: 1px solid var(--line);
      padding: 20px 40px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand {
      font-size: 14px;
      font-weight: 600;
      text-transform: uppercase;
      text-decoration: none;
      color: var(--ink);
    }
    .nav-links { display: flex; gap: 20px; align-items: center; font-size: 13px; }
    .nav-links a { color: var(--muted); text-decoration: none; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    .nav-links a:hover { color: var(--ink); text-decoration: underline; }
    .status-pill {
      display: inline-flex; align-items: center; gap: 7px;
      font-family: 'JetBrains Mono', monospace; font-size: 11px;
      color: var(--badge); background: var(--accent-light);
      padding: 4px 10px; border-radius: 999px;
    }
    .status-dot { width: 6px; height: 6px; background: #2b8a53; border-radius: 50%; animation: pulse 2s infinite; }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(43, 138, 83, 0.5); }
      70% { box-shadow: 0 0 0 6px rgba(43, 138, 83, 0); }
      100% { box-shadow: 0 0 0 0 rgba(43, 138, 83, 0); }
    }
    main { max-width: 1140px; margin: 0 auto; padding: 50px 24px 80px; }
    h1 {
      font-family: 'Instrument Serif', Georgia, serif;
      font-size: 46px; font-weight: 400; line-height: 1.1; margin-bottom: 10px;
    }
    .sub { color: var(--muted); margin-bottom: 40px; font-size: 15px; }
    .grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
      gap: 24px; margin-bottom: 32px;
    }
    .card {
      background: var(--surface); border: 1px solid var(--line); padding: 28px; margin-bottom: 24px;
    }
    .card h2 {
      font-family: 'Instrument Serif', Georgia, serif;
      font-size: 26px; font-weight: 400; margin-bottom: 16px;
    }
    .card-header {
      display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;
    }
    .card-header h2 { margin-bottom: 0; }
    .metric-row {
      display: flex; justify-content: space-between; padding: 10px 0;
      border-top: 1px solid var(--line); font-size: 13px;
    }
    .metric-row span:first-child { color: var(--muted); }
    .metric-row span:last-child { font-family: 'JetBrains Mono', monospace; font-weight: 500; text-align: right; }
    .countdown {
      font-family: 'Instrument Serif', Georgia, serif;
      font-size: 48px; color: var(--badge); line-height: 1; margin: 10px 0 18px;
    }
    .countdown small { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--muted); display: block; margin-top: 4px; }
    .bar-bg { width: 100%; height: 6px; background: #eeebe3; margin: 6px 0 14px; }
    .bar-fill { height: 100%; background: var(--ink); }
    .lookup-form { display: flex; gap: 10px; margin-top: 14px; }
    input {
      flex: 1; padding: 10px 12px; border: 1px solid var(--line);
      background: var(--bg); font-family: 'JetBrains Mono', monospace; font-size: 13px;
    }
    button {
      padding: 10px 18px; background: var(--ink); color: var(--bg);
      border: none; font-size: 13px; cursor: pointer; font-weight: 500;
    }
    button.btn-outline {
      background: transparent; color: var(--ink); border: 1px solid var(--line);
      font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 6px 12px;
    }
    button.btn-outline:hover { border-color: var(--ink); }
    pre {
      background: var(--bg); border: 1px solid var(--line); padding: 14px;
      margin-top: 14px; font-family: 'JetBrains Mono', monospace; font-size: 12px;
      overflow-x: auto; display: none;
    }
    .table-pills {
      display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 24px;
    }
    .tbl-pill {
      font-family: 'JetBrains Mono', monospace; font-size: 12px;
      background: var(--bg); border: 1px solid var(--line); padding: 6px 12px;
    }
    .tbl-pill strong { color: var(--ink); }
    .data-table-wrap { overflow-x: auto; margin-top: 10px; margin-bottom: 28px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th {
      text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 11px;
      text-transform: uppercase; color: var(--muted); padding: 10px 8px;
      border-bottom: 1px solid var(--line); white-space: nowrap;
    }
    td {
      padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top;
    }
    .mono { font-family: 'JetBrains Mono', monospace; font-size: 11px; }
    .hash-cell { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--badge); }
    .token-badge {
      font-family: 'JetBrains Mono', monospace; font-size: 11px;
      background: var(--accent-light); color: var(--badge); padding: 2px 6px;
    }
    .section-label {
      font-family: 'JetBrains Mono', monospace; font-size: 11px; text-transform: uppercase;
      color: var(--muted); margin-bottom: 8px; letter-spacing: 0.05em;
    }
  </style>
</head>
<body>
  <header>
    <a href="https://trigun.me" class="brand">API & Telemetry</a>
    <div class="nav-links">
      <div class="status-pill"><span class="status-dot"></span> <?= htmlspecialchars($dbStatus) ?></div>
      <a href="?format=json" target="_blank">Raw JSON ↗</a>
      <a href="https://trigun.me">← Home</a>
    </div>
  </header>

  <main>
    <h1>Infrastructure & Live Database</h1>
    <p class="sub">Real-time system health, ZeroSSL certificate lifecycle, and live MySQL inspector.</p>

    <div class="grid">
      <!-- Card 1: ZeroSSL Health -->
      <div class="card" style="margin-bottom: 0;">
        <h2>ZeroSSL Certificate</h2>
        <div class="countdown">
          <?= $sslData['days_left'] ?> Days
          <small>REMAINING UNTIL EXPIRY (<?= htmlspecialchars($sslData['valid_to']) ?>)</small>
        </div>
        <div class="metric-row"><span>Status</span><span><?= htmlspecialchars($sslData['status']) ?></span></div>
        <div class="metric-row"><span>Issuer CA</span><span><?= htmlspecialchars($sslData['issuer']) ?></span></div>
        <div class="metric-row"><span>Issued On</span><span><?= htmlspecialchars($sslData['valid_from']) ?></span></div>
        <div class="metric-row"><span>Covered Domains</span><span style="font-size:11px;"><?= htmlspecialchars($sslData['sans']) ?></span></div>
      </div>

      <!-- Card 2: Compute & Memory -->
      <div class="card" style="margin-bottom: 0;">
        <h2>Compute & Memory</h2>
        <p style="font-size:12px; color:var(--muted);">RAM Usage (<?= $memUsedMB ?> / <?= $memTotalMB ?> MB — <?= $memPercent ?>%)</p>
        <div class="bar-bg"><div class="bar-fill" style="width: <?= min(100, $memPercent) ?>%;"></div></div>

        <p style="font-size:12px; color:var(--muted);">Disk Usage (<?= $diskUsedGB ?> / <?= $diskTotalGB ?> GB — <?= $diskPercent ?>%)</p>
        <div class="bar-bg"><div class="bar-fill" style="width: <?= min(100, $diskPercent) ?>%;"></div></div>

        <div class="metric-row"><span>CPU Load (1m / 5m)</span><span><?= $load[0] ?> / <?= $load[1] ?></span></div>
        <div class="metric-row"><span>System Uptime</span><span><?= htmlspecialchars($uptimeText) ?></span></div>
        <div class="metric-row"><span>PHP Runtime</span><span><?= phpversion() ?></span></div>
      </div>

      <!-- Card 3: MySQL Database State -->
      <div class="card" style="margin-bottom: 0;">
        <h2>Database Engine</h2>
        <div class="metric-row"><span>Connection</span><span><?= htmlspecialchars($dbStatus) ?></span></div>
        <div class="metric-row"><span>Engine Version</span><span>MySQL <?= htmlspecialchars($mysqlVersion) ?></span></div>
        <div class="metric-row"><span>Registered Users</span><span id="topUserCount"><?= $userCount ?></span></div>
        <div class="metric-row"><span>Filed Incidents</span><span id="topIncidentCount"><?= $incidentCount ?></span></div>
        <div class="metric-row"><span>Host Server</span><span>Microsoft Azure</span></div>
      </div>
    </div>

    <!-- Real-Time Database Inspector -->
    <div class="card">
      <div class="card-header">
        <h2>Real-Time MySQL Database Inspector</h2>
        <div style="display:flex; align-items:center; gap:12px;">
          <span class="status-pill" id="liveBadge"><span class="status-dot" id="liveDot"></span> <span id="liveText">LIVE · Syncing every 3s</span></span>
          <button type="button" class="btn-outline" id="toggleLiveBtn" onclick="toggleLive()">Pause</button>
        </div>
      </div>

      <div class="section-label">Tables in `incident_portal` (<span id="lastSyncTime">Loading...</span>)</div>
      <div class="table-pills" id="tablePills"></div>

      <div class="section-label">Table: `users` (Live BCRYPT Password Hashing Proof)</div>
      <div class="data-table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Full Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Stored Password Hash (MySQL)</th>
            </tr>
          </thead>
          <tbody id="usersBody">
            <tr><td colspan="5" style="color:var(--muted);">Loading live rows...</td></tr>
          </tbody>
        </table>
      </div>

      <div class="section-label">Table: `incidents` (Latest Campus Reports)</div>
      <div class="data-table-wrap" style="margin-bottom: 0;">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Tracking Token</th>
              <th>Title</th>
              <th>Category</th>
              <th>Priority</th>
              <th>Status</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody id="incidentsBody">
            <tr><td colspan="7" style="color:var(--muted);">Loading live rows...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Token API Tester -->
    <div class="card">
      <h2>REST API Token Lookup</h2>
      <p style="color:var(--muted); font-size:13px;">Query an incident tracking token against <code>https://api.trigun.me/?token=INC-XXXX</code></p>
      <form class="lookup-form" onsubmit="lookupToken(event)">
        <input type="text" id="tokenInput" placeholder="Enter Tracking Token (e.g. INC-8F4A2B1C)" required>
        <button type="submit">Query API ↳</button>
      </form>
      <pre id="apiOutput"></pre>
    </div>
  </main>

  <script>
    let isLive = true;
    let pollTimer = null;

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    async function fetchLiveDb() {
      try {
        const res = await fetch('?live_db=1');
        const data = await res.json();

        document.getElementById('lastSyncTime').textContent = 'Last sync: ' + data.timestamp;

        // Update table pills
        const pillsHtml = data.tables.map(t =>
          `<div class="tbl-pill">${escapeHtml(t.name)}: <strong>${t.rows}</strong></div>`
        ).join('');
        document.getElementById('tablePills').innerHTML = pillsHtml;

        // Update top counts
        const uTbl = data.tables.find(t => t.name === 'users');
        const iTbl = data.tables.find(t => t.name === 'incidents');
        if (uTbl) document.getElementById('topUserCount').textContent = uTbl.rows;
        if (iTbl) document.getElementById('topIncidentCount').textContent = iTbl.rows;

        // Render users table
        if (data.users.length === 0) {
          document.getElementById('usersBody').innerHTML = '<tr><td colspan="5" style="color:var(--muted);">No registered users yet.</td></tr>';
        } else {
          document.getElementById('usersBody').innerHTML = data.users.map(u => `
            <tr>
              <td class="mono">${u.id}</td>
              <td>${escapeHtml(u.full_name)}</td>
              <td class="mono">${escapeHtml(u.email)}</td>
              <td class="mono" style="text-transform:uppercase;">${escapeHtml(u.role)}</td>
              <td class="mono hash-cell" title="${escapeHtml(u.password_hash)}">${escapeHtml(u.password_hash)}</td>
            </tr>
          `).join('');
        }

        // Render incidents table
        if (data.incidents.length === 0) {
          document.getElementById('incidentsBody').innerHTML = '<tr><td colspan="7" style="color:var(--muted);">No incidents reported yet.</td></tr>';
        } else {
          document.getElementById('incidentsBody').innerHTML = data.incidents.map(inc => `
            <tr>
              <td class="mono">${inc.id}</td>
              <td><span class="token-badge">${escapeHtml(inc.tracking_token || 'N/A')}</span></td>
              <td>${escapeHtml(inc.title)}</td>
              <td>${escapeHtml(inc.category || 'General')}</td>
              <td style="text-transform:capitalize;">${escapeHtml(inc.priority)}</td>
              <td style="text-transform:capitalize; font-weight:500;">${escapeHtml(inc.status)}</td>
              <td class="mono" style="color:var(--muted);">${escapeHtml(inc.created_at)}</td>
            </tr>
          `).join('');
        }
      } catch (err) {
        console.error('Live DB sync failed:', err);
      }
    }

    function toggleLive() {
      isLive = !isLive;
      const btn = document.getElementById('toggleLiveBtn');
      const txt = document.getElementById('liveText');
      const dot = document.getElementById('liveDot');

      if (isLive) {
        btn.textContent = 'Pause';
        txt.textContent = 'LIVE · Syncing every 3s';
        dot.style.display = 'inline-block';
        fetchLiveDb();
        pollTimer = setInterval(fetchLiveDb, 3000);
      } else {
        btn.textContent = 'Resume';
        txt.textContent = 'PAUSED';
        dot.style.display = 'none';
        clearInterval(pollTimer);
      }
    }

    // Start polling immediately
    fetchLiveDb();
    pollTimer = setInterval(fetchLiveDb, 3000);

    async function lookupToken(e) {
      e.preventDefault();
      const token = document.getElementById('tokenInput').value.trim();
      const output = document.getElementById('apiOutput');
      output.style.display = 'block';
      output.textContent = 'Querying https://api.trigun.me/?token=' + encodeURIComponent(token) + '...';
      try {
        const res = await fetch('?token=' + encodeURIComponent(token));
        const data = await res.json();
        output.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        output.textContent = 'Error: ' + err.message;
      }
    }
  </script>
</body>
</html>
