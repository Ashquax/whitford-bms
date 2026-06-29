// =======================================================
// Whitford Building Management System v2
// Railway + PostgreSQL + Roblox Integration
// =======================================================

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);

const app = express();

app.set("trust proxy", 1);
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 8080;
const SECRET = process.env.BMS_SECRET || "CHANGE_THIS_SECRET";
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.use(session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 8,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax"
  }
}));

let songs = [];

let latestCommand = {
  id: 0,
  command: "none",
  songNumber: null,
  controlsLocked: false
};

let latestAccessCommand = {
  id: 0,
  command: "none",
  value: null
};

let bmsState = {
  fire: "normal",
  fireLive: "offline",
  controlsLocked: false,
  activeFire: null,
  fireEvents: [],
  fireDevices: [],
  fireZones: [],
  fireNodes: [],

  music: "stopped",
  currentSongNumber: null,
  currentSongId: null,

  lifts: "offline",
  liftData: [],

  access: "offline",
  accessDoors: [],

  lastRobloxUpdate: null,
  version: "2.0.0"
};

function checkSecret(req, res) {
  const secret = req.body.secret || req.query.secret;

  if (secret !== SECRET) {
    res.status(403).json({ error: "Bad secret" });
    return false;
  }

  return true;
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }

  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.status(401).json({ error: "Not logged in" });
    }

    if (!roles.includes(req.session.user.role)) {
      return res.status(403).json({ error: "No permission" });
    }

    next();
  };
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('operator', 'supervisor', 'administrator')),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS event_log (
      id SERIAL PRIMARY KEY,
      type TEXT NOT NULL,
      data JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
}

async function logEvent(type, data) {
  try {
    await pool.query(
      "INSERT INTO event_log (type, data) VALUES ($1, $2)",
      [type, data]
    );
  } catch (err) {
    console.error("Log error:", err);
  }
}
app.get("/setup", async (req, res) => {
  const count = await pool.query("SELECT COUNT(*) FROM users");

  if (Number(count.rows[0].count) > 0) {
    return res.redirect("/");
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Whitford BMS Setup</title>
<style>
body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#eef0f3; color:#1f2933; }
.topbar { height:6px; background:#e20015; }
.box { max-width:460px; margin:80px auto; background:white; padding:34px; border-radius:6px; box-shadow:0 8px 25px rgba(0,0,0,0.14); }
h1 { margin-top:0; }
input { width:100%; box-sizing:border-box; padding:13px; margin:8px 0 16px; border:1px solid #c8ccd2; border-radius:4px; }
button { width:100%; background:#e20015; color:white; border:0; padding:14px; font-weight:bold; cursor:pointer; border-radius:4px; }
button:hover { background:#b80012; }
.msg { margin-top:15px; color:#e20015; font-weight:bold; }
</style>
</head>
<body>
<div class="topbar"></div>
<div class="box">
  <h1>Whitford BMS</h1>
  <p>Initial administrator setup</p>
  <input id="username" placeholder="Administrator username">
  <input id="password" type="password" placeholder="Password">
  <input id="confirm" type="password" placeholder="Confirm password">
  <button onclick="createAdmin()">Create Administrator</button>
  <div class="msg" id="msg"></div>
</div>

<script>
async function createAdmin() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const confirm = document.getElementById("confirm").value;

  if (!username || !password) {
    document.getElementById("msg").textContent = "Enter a username and password.";
    return;
  }

  if (password !== confirm) {
    document.getElementById("msg").textContent = "Passwords do not match.";
    return;
  }

  const res = await fetch("/api/setup/create-admin", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ username, password })
  });

  const data = await res.json();

  if (!res.ok) {
    document.getElementById("msg").textContent = data.error || "Setup failed.";
    return;
  }

  window.location.href = "/";
}
</script>
</body>
</html>
  `);
});

app.post("/api/setup/create-admin", async (req, res) => {
  const count = await pool.query("SELECT COUNT(*) FROM users");

  if (Number(count.rows[0].count) > 0) {
    return res.status(403).json({ error: "Setup already completed" });
  }

  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  await pool.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)",
    [username, passwordHash, "administrator"]
  );

  await logEvent("setup_admin_created", { username });

  res.json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1",
    [username]
  );

  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const ok = await bcrypt.compare(password, user.password_hash);

  if (!ok) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role
  };

  await logEvent("user_login", {
    username: user.username,
    role: user.role
  });

  res.json({ ok: true, user: req.session.user });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/auth/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.get("/api/state", requireLogin, (req, res) => {
  res.json(bmsState);
});

app.get("/api/events", requireLogin, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM event_log ORDER BY id DESC LIMIT 100"
  );

  res.json({ events: result.rows });
});
app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Whitford Building Management System</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: Arial, Helvetica, sans-serif;
  background: #eef0f3;
  color: #1f2933;
}

.bosch-strip {
  height: 6px;
  background: #e20015;
}

.header {
  height: 64px;
  background: white;
  border-bottom: 1px solid #d8dce2;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
}

.logo {
  font-size: 22px;
  font-weight: bold;
}

.logo span {
  color: #e20015;
}

.userbar {
  color: #6b7280;
  font-size: 14px;
}

.layout {
  display: flex;
  height: calc(100vh - 118px);
}

.sidebar {
  width: 250px;
  background: #26313f;
  color: white;
  padding-top: 18px;
  flex-shrink: 0;
}

.nav {
  padding: 15px 24px;
  border-left: 4px solid transparent;
  cursor: pointer;
  user-select: none;
}

.nav:hover,
.nav.active {
  background: #1d2631;
  border-left-color: #e20015;
}

.main {
  flex: 1;
  padding: 24px;
  overflow: auto;
}

.hidden {
  display: none !important;
}

.page-title {
  margin-top: 0;
}

.card {
  background: white;
  border: 1px solid #d8dce2;
  border-radius: 5px;
  padding: 20px;
  margin-bottom: 18px;
}

.grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 18px;
}

.status-card {
  background: white;
  border-top: 5px solid #9ca3af;
  border-radius: 5px;
  padding: 20px;
  min-height: 120px;
}

.status-card.ok {
  border-top-color: #00884a;
}

.status-card.alarm {
  border-top-color: #e20015;
}

.status-card.warning {
  border-top-color: #f59e0b;
}

.status-title {
  font-size: 14px;
  color: #6b7280;
}

.status-value {
  font-size: 28px;
  margin-top: 12px;
  font-weight: bold;
}

button {
  background: #e20015;
  color: white;
  border: 0;
  padding: 11px 16px;
  margin: 5px;
  cursor: pointer;
  border-radius: 4px;
  font-weight: bold;
}

button:hover {
  background: #b80012;
}

button:disabled {
  background: #9ca3af;
  cursor: not-allowed;
}

input,
select {
  padding: 11px;
  border: 1px solid #c8ccd2;
  border-radius: 4px;
  min-width: 260px;
}

.login-box {
  max-width: 420px;
  margin: 90px auto;
  background: white;
  padding: 34px;
  box-shadow: 0 8px 25px rgba(0,0,0,0.12);
  border-radius: 5px;
}

.alarm-text {
  color: #e20015;
  font-weight: bold;
}

.event {
  padding: 10px;
  border-bottom: 1px solid #e5e7eb;
  font-size: 14px;
}

.badge {
  display: inline-block;
  padding: 5px 10px;
  border-radius: 20px;
  font-size: 13px;
  font-weight: bold;
}

.badge-ok {
  background: #d9f7e8;
  color: #00884a;
}

.badge-alarm {
  background: #ffe1e4;
  color: #e20015;
}

.badge-warning {
  background: #fff3cd;
  color: #a16207;
}

.alarm-row {
  background: #ffe1e4;
  font-weight: bold;
}

.table {
  width: 100%;
  border-collapse: collapse;
}

.table th,
.table td {
  text-align: left;
  padding: 10px;
  border-bottom: 1px solid #e5e7eb;
}

.table th {
  background: #f8fafc;
  font-size: 13px;
  color: #374151;
}

.small {
  color: #6b7280;
  font-size: 13px;
}

.status-ribbon {
  display: flex;
  gap: 12px;
  padding: 12px 24px;
  background: #111827;
  color: white;
  border-bottom: 1px solid #374151;
  overflow-x: auto;
}

.ribbon-item {
  padding: 8px 14px;
  border-radius: 20px;
  font-weight: bold;
  font-size: 13px;
  background: #374151;
  white-space: nowrap;
}

.ribbon-ok {
  background: #00884a;
}

.ribbon-alarm {
  background: #e20015;
}

.ribbon-warning {
  background: #f59e0b;
}

.big-alarm-banner {
  display: none;
  background: #e20015;
  color: white;
  padding: 22px;
  font-size: 24px;
  font-weight: bold;
  margin-bottom: 20px;
  border-radius: 4px;
  animation: pulseAlarm 1s infinite;
}

@keyframes pulseAlarm {
  0% { opacity: 1; }
  50% { opacity: 0.75; }
  100% { opacity: 1; }
}

.device-search-row {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 14px;
}

@media (max-width: 1100px) {
  .grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .layout {
    height: auto;
    min-height: calc(100vh - 118px);
  }
}

@media (max-width: 800px) {
  .layout {
    flex-direction: column;
  }

  .sidebar {
    width: 100%;
  }

  .grid {
    grid-template-columns: 1fr;
  }
}
</style>
</head>

<body>
<div class="bosch-strip"></div>

<div id="loginBox" class="login-box">
  <h1>Whitford BMS</h1>
  <p>Building Management System Login</p>
  <input id="username" placeholder="Username"><br><br>
  <input id="password" type="password" placeholder="Password"><br><br>
  <button onclick="login()">Login</button>
  <p id="loginMsg" class="alarm-text"></p>
  <p><a href="/setup">First-time setup</a></p>
</div>

<div id="appBox" class="hidden">
  <div class="header">
    <div class="logo"><span>Whitford</span> Building Management System</div>
    <div class="userbar">
      <span id="clock">--:--:--</span>
      &nbsp; | &nbsp;
      <span id="user"></span> | <span id="role"></span>
      <button onclick="logout()">Logout</button>
    </div>
  </div>

  <div class="status-ribbon">
    <div class="ribbon-item" id="ribbonFire">🔥 Fire</div>
    <div class="ribbon-item" id="ribbonMusic">🎵 Music</div>
    <div class="ribbon-item" id="ribbonLifts">🛗 Lifts</div>
    <div class="ribbon-item" id="ribbonAccess">🚪 Access</div>
    <div class="ribbon-item ribbon-ok" id="ribbonOnline">🟢 Online</div>
  </div>

  <div class="layout">
    <div class="sidebar">
      <div class="nav active" onclick="showPage('dashboard', this)">Dashboard</div>
      <div class="nav" onclick="showPage('fire', this)">Fire Alarm</div>
      <div class="nav" onclick="showPage('music', this)">Music</div>
      <div class="nav" onclick="showPage('lifts', this)">Lifts</div>
      <div class="nav" onclick="showPage('access', this)">Access Control</div>
      <div class="nav" onclick="showPage('events', this)">Event Log</div>
      <div class="nav" onclick="showPage('settings', this)">Settings</div>
    </div>

    <div class="main">
      <div id="bigAlarmBanner" class="big-alarm-banner">🔥 FIRE ALARM ACTIVE</div>

      <div id="page-dashboard" class="page">
        <h1 class="page-title">Dashboard</h1>

        <div class="grid">
          <div class="status-card" id="fireCard">
            <div class="status-title">Fire Alarm</div>
            <div class="status-value" id="fire">---</div>
          </div>

          <div class="status-card ok">
            <div class="status-title">Music</div>
            <div class="status-value" id="music">---</div>
          </div>

          <div class="status-card ok">
            <div class="status-title">Lifts</div>
            <div class="status-value" id="lifts">---</div>
          </div>

          <div class="status-card ok">
            <div class="status-title">Access Control</div>
            <div class="status-value" id="access">---</div>
          </div>
        </div>

        <div class="card">
          <h2>System Lock Status</h2>
          <p>Controls Locked: <span id="locked"></span></p>
          <p>Current Song: <span id="song"></span></p>
          <p>Last Roblox Update: <span id="lastRobloxUpdate">---</span></p>
        </div>

        <div class="card">
          <h2>Recent Events</h2>
          <div id="eventsDash"></div>
        </div>
      </div>
            <div id="page-fire" class="page hidden">
        <h1 class="page-title">Fire Alarm Monitoring</h1>

        <div class="card">
          <h2>Lumina Fire System</h2>
          <p>Status: <span id="firePageStatus"></span></p>
          <p>Live Monitor: <span id="fireLiveStatus">---</span></p>
          <p>Controls Locked: <span id="firePageLocked"></span></p>
          <p class="small">Live zones and devices are sent from the Lumina panel in Roblox.</p>
        </div>

        <div class="grid">
          <div class="status-card ok">
            <div class="status-title">Nodes</div>
            <div class="status-value" id="fireNodeCount">0</div>
          </div>

          <div class="status-card ok">
            <div class="status-title">Zones</div>
            <div class="status-value" id="fireZoneCount">0</div>
          </div>

          <div class="status-card ok">
            <div class="status-title">Devices</div>
            <div class="status-value" id="fireDeviceCount">0</div>
          </div>

          <div class="status-card alarm">
            <div class="status-title">Alarms</div>
            <div class="status-value" id="fireAlarmCount">0</div>
          </div>
        </div>

        <div class="grid">
          <div class="status-card warning">
            <div class="status-title">Faults</div>
            <div class="status-value" id="fireFaultCount">0</div>
          </div>

          <div class="status-card warning">
            <div class="status-title">Isolated</div>
            <div class="status-value" id="fireIsolatedCount">0</div>
          </div>

          <div class="status-card ok">
            <div class="status-title">Normal Devices</div>
            <div class="status-value" id="fireNormalCount">0</div>
          </div>

          <div class="status-card ok">
            <div class="status-title">System Version</div>
            <div class="status-value" id="systemVersion">---</div>
          </div>
        </div>

        <div class="card">
          <h2>Zones</h2>
          <table class="table">
            <thead>
              <tr>
                <th>Node</th>
                <th>Zone</th>
                <th>Status</th>
                <th>Devices</th>
                <th>Alarms</th>
                <th>Faults</th>
                <th>Isolated</th>
              </tr>
            </thead>
            <tbody id="fireZonesTable">
              <tr>
                <td colspan="7">Waiting for live zone data...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="card">
          <h2>Devices</h2>

          <div class="device-search-row">
            <input id="fireDeviceSearch" placeholder="Search devices, zones, loops, nodes, locations..." oninput="renderFireDevices()">
            <select id="fireStatusFilter" onchange="renderFireDevices()">
              <option value="">All statuses</option>
              <option value="normal">Normal</option>
              <option value="alarm">Alarm</option>
              <option value="fault">Fault</option>
              <option value="isolated">Isolated</option>
            </select>
          </div>

          <table class="table">
            <thead>
              <tr>
                <th>Node</th>
                <th>Loop</th>
                <th>Zone</th>
                <th>Device</th>
                <th>Type</th>
                <th>Status</th>
                <th>Location</th>
                <th>Serial</th>
              </tr>
            </thead>
            <tbody id="fireDevicesTable">
              <tr>
                <td colspan="8">Waiting for live device data...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div id="page-music" class="page hidden">
        <h1 class="page-title">Music Control</h1>

        <div class="card">
          <h2>Playback</h2>
          <p>Status: <span id="musicPageStatus"></span></p>
          <p>Current Song Number: <span id="musicPageSong"></span></p>
          <p>Current Song ID: <span id="musicPageSongId"></span></p>

          <button class="controlBtn" onclick="sendCommand('play')">Play</button>
          <button class="controlBtn" onclick="sendCommand('pause')">Pause</button>
          <button class="controlBtn" onclick="sendCommand('stop')">Stop</button>
        </div>

        <div class="card">
          <h2>Song Library From Roblox</h2>
          <select id="songList"></select>
          <button class="controlBtn" onclick="playSelected()">Play Selected Song</button>
          <p class="small">Songs are uploaded from your Roblox MusicSettings module. The list will not auto-jump while you are selecting.</p>
        </div>
      </div>

      <div id="page-lifts" class="page hidden">
        <h1 class="page-title">Lift Monitoring</h1>

        <div class="card">
          <h2>Lift System</h2>
          <p>Status: <span id="liftsPageStatus"></span></p>

          <table class="table">
            <thead>
              <tr>
                <th>Lift</th>
                <th>Group</th>
                <th>Floor</th>
                <th>Direction</th>
                <th>Doors</th>
                <th>Status</th>
                <th>Fire Recall</th>
                <th>Served Floors</th>
              </tr>
            </thead>
            <tbody id="liftTable">
              <tr>
                <td colspan="8">Waiting for lift data...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div id="page-access" class="page hidden">
        <h1 class="page-title">Access Control</h1>

        <div class="card">
          <h2>Door System</h2>
          <p>Status: <span id="accessPageStatus"></span></p>

          <button class="controlBtn" onclick="sendAccess('lock')">Lock All Doors</button>
          <button class="controlBtn" onclick="sendAccess('unlock')">Unlock All Doors</button>
          <button class="controlBtn" onclick="sendAccess('hold_open')">Hold Open</button>
          <button class="controlBtn" onclick="sendAccess('release_hold')">Release Hold</button>
          <button class="controlBtn" onclick="sendAccess('fire')">Fire Release</button>
          <button class="controlBtn" onclick="sendAccess('reset')">Reset Releases</button>
          <button class="controlBtn" onclick="sendAccess('open', 10)">Open 10 Seconds</button>
        </div>

        <div class="card">
          <h2>Door Status</h2>
          <table class="table">
            <thead>
              <tr>
                <th>Door</th>
                <th>Status</th>
                <th>Lock</th>
                <th>Mode</th>
              </tr>
            </thead>
            <tbody id="accessDoorTable">
              <tr>
                <td colspan="4">Waiting for access data...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div id="page-events" class="page hidden">
        <h1 class="page-title">Event Log</h1>

        <div class="card">
          <h2>Latest Events</h2>
          <div id="events"></div>
        </div>
      </div>

      <div id="page-settings" class="page hidden">
        <h1 class="page-title">Settings</h1>

        <div class="card">
          <h2>User Permissions</h2>
          <p><b>Operator:</b> View only</p>
          <p><b>Supervisor:</b> Music and Access control</p>
          <p><b>Administrator:</b> Full access</p>
        </div>

        <div class="card">
          <h2>System Information</h2>
          <p>Whitford BMS v<span id="settingsVersion">---</span></p>
          <p>Railway + PostgreSQL + Roblox Integration</p>
        </div>
      </div>
          </div>
  </div>
</div>

<script>
let currentUser = null;
let latestState = null;

function showPage(page, el) {
  document.querySelectorAll(".page").forEach(function(p) {
    p.classList.add("hidden");
  });

  const pageEl = document.getElementById("page-" + page);

  if (pageEl) {
    pageEl.classList.remove("hidden");
  }

  document.querySelectorAll(".nav").forEach(function(n) {
    n.classList.remove("active");
  });

  if (el) {
    el.classList.add("active");
  }

  if (page === "music") {
    loadSongs();
  }
}

function updateClock() {
  const clock = document.getElementById("clock");

  if (!clock) return;

  const now = new Date();

  clock.textContent = now.toLocaleString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    day: "2-digit",
    month: "2-digit",
    year: "numeric"
  });
}

async function checkLogin() {
  const res = await fetch("/api/auth/me");
  const data = await res.json();

  if (data.user) {
    currentUser = data.user;

    document.getElementById("loginBox").classList.add("hidden");
    document.getElementById("appBox").classList.remove("hidden");

    document.getElementById("user").textContent = currentUser.username;
    document.getElementById("role").textContent = currentUser.role;

    await loadState();
    await loadSongs();
    await loadEvents();
  } else {
    currentUser = null;

    document.getElementById("loginBox").classList.remove("hidden");
    document.getElementById("appBox").classList.add("hidden");
  }
}

async function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      username,
      password
    })
  });

  const data = await res.json();

  if (!res.ok) {
    document.getElementById("loginMsg").textContent =
      data.error || "Login failed";
    return;
  }

  document.getElementById("loginMsg").textContent = "";

  await checkLogin();
}

async function logout() {
  await fetch("/api/auth/logout", {
    method: "POST"
  });

  currentUser = null;

  await checkLogin();
}

async function loadState() {
  if (!currentUser) return;

  const res = await fetch("/api/state");

  if (!res.ok) {
    console.warn("State failed:", res.status);
    return;
  }

  const data = await res.json();

  latestState = data;

  updateDashboard(data);
  updateFirePage(data);
  updateMusicPage(data);
  updateLiftPage(data);
  updateAccessPage(data);
  updateRibbon(data);
  updateControlLocks(data);
}

function setText(id, value) {
  const el = document.getElementById(id);

  if (el) {
    el.textContent = value;
  }
}

function setHTML(id, value) {
  const el = document.getElementById(id);

  if (el) {
    el.innerHTML = value;
  }
}

function badge(status) {
  if (status === "alarm") {
    return "badge badge-alarm";
  }

  if (status === "fault" || status === "isolated" || status === "disabled") {
    return "badge badge-warning";
  }

  return "badge badge-ok";
}

function normaliseStatus(status) {
  return String(status || "normal").toLowerCase();
}

function safeValue(value, fallback) {
  if (value === undefined || value === null || value === "") {
    return fallback || "Unknown";
  }

  return value;
}
function updateDashboard(data) {
  setText("fire", data.fire || "normal");
  setText("music", data.music || "stopped");
  setText("lifts", data.lifts || "offline");
  setText("access", data.access || "offline");
  setText("locked", data.controlsLocked ? "true" : "false");
  setText("song", data.currentSongNumber || "None");
  setText("systemVersion", data.version || "2.0.0");
  setText("settingsVersion", data.version || "2.0.0");

  if (data.lastRobloxUpdate) {
    setText(
      "lastRobloxUpdate",
      new Date(data.lastRobloxUpdate).toLocaleString()
    );
  } else {
    setText("lastRobloxUpdate", "No Roblox update yet");
  }

  const fireCard = document.getElementById("fireCard");

  if (fireCard) {
    fireCard.className =
      data.fire === "alarm"
        ? "status-card alarm"
        : "status-card ok";
  }
}

function updateRibbon(data) {
  const fire = document.getElementById("ribbonFire");
  const music = document.getElementById("ribbonMusic");
  const lifts = document.getElementById("ribbonLifts");
  const access = document.getElementById("ribbonAccess");
  const online = document.getElementById("ribbonOnline");
  const banner = document.getElementById("bigAlarmBanner");

  if (fire) {
    fire.className =
      data.fire === "alarm"
        ? "ribbon-item ribbon-alarm"
        : "ribbon-item ribbon-ok";

    fire.textContent =
      data.fire === "alarm"
        ? "🔥 Fire Alarm"
        : "🔥 Fire Normal";
  }

  if (music) {
    music.className =
      data.music === "fire_locked"
        ? "ribbon-item ribbon-warning"
        : "ribbon-item ribbon-ok";

    music.textContent = "🎵 " + (data.music || "stopped");
  }

  if (lifts) {
    lifts.className =
      data.lifts === "offline"
        ? "ribbon-item ribbon-warning"
        : "ribbon-item ribbon-ok";

    lifts.textContent = "🛗 " + (data.lifts || "offline");
  }

  if (access) {
    access.className =
      data.access === "offline"
        ? "ribbon-item ribbon-warning"
        : "ribbon-item ribbon-ok";

    access.textContent = "🚪 " + (data.access || "offline");
  }

  if (online) {
    const age = data.lastRobloxUpdate
      ? Date.now() - new Date(data.lastRobloxUpdate).getTime()
      : Infinity;

    const isOnline = age < 15000;

    online.className = isOnline
      ? "ribbon-item ribbon-ok"
      : "ribbon-item ribbon-warning";

    online.textContent = isOnline
      ? "🟢 Roblox Online"
      : "🟠 Roblox Offline";
  }

  if (banner) {
    if (data.fire === "alarm") {
      banner.style.display = "block";

      if (data.activeFire) {
        banner.textContent =
          "🔥 FIRE ALARM ACTIVE — " +
          "Node " +
          safeValue(data.activeFire.node, "?") +
          " | Loop " +
          safeValue(data.activeFire.loop, "?") +
          " | Zone " +
          safeValue(data.activeFire.zone, "?") +
          " | " +
          safeValue(
            data.activeFire.deviceName || data.activeFire.device,
            "Unknown Device"
          );
      } else {
        banner.textContent = "🔥 FIRE ALARM ACTIVE";
      }
    } else {
      banner.style.display = "none";
    }
  }
}

function updateFirePage(data) {
  const devices = Array.isArray(data.fireDevices)
    ? data.fireDevices
    : [];

  const zones = Array.isArray(data.fireZones)
    ? data.fireZones
    : [];

  const nodes = Array.isArray(data.fireNodes)
    ? data.fireNodes
    : [];

  const alarmCount = devices.filter(function(d) {
    return normaliseStatus(d.status) === "alarm";
  }).length;

  const faultCount = devices.filter(function(d) {
    return normaliseStatus(d.status) === "fault";
  }).length;

  const isolatedCount = devices.filter(function(d) {
    const s = normaliseStatus(d.status);
    return s === "isolated" || s === "disabled";
  }).length;

  const normalCount = devices.filter(function(d) {
    return normaliseStatus(d.status) === "normal";
  }).length;

  setText(
    "firePageStatus",
    data.fire === "alarm" ? "ALARM" : "NORMAL"
  );

  const firePageStatus = document.getElementById("firePageStatus");

  if (firePageStatus) {
    firePageStatus.innerHTML =
      data.fire === "alarm"
        ? "<span class='badge badge-alarm'>ALARM</span>"
        : "<span class='badge badge-ok'>NORMAL</span>";
  }

  setText("fireLiveStatus", data.fireLive || "offline");
  setText("firePageLocked", data.controlsLocked ? "true" : "false");
  setText("fireNodeCount", nodes.length);
  setText("fireZoneCount", zones.length);
  setText("fireDeviceCount", devices.length);
  setText("fireAlarmCount", alarmCount);
  setText("fireFaultCount", faultCount);
  setText("fireIsolatedCount", isolatedCount);
  setText("fireNormalCount", normalCount);

  renderFireZones();
  renderFireDevices();
}

function renderFireZones() {
  const table = document.getElementById("fireZonesTable");

  if (!table || !latestState) return;

  const zones = Array.isArray(latestState.fireZones)
    ? latestState.fireZones
    : [];

  if (zones.length === 0) {
    table.innerHTML =
      "<tr><td colspan='7'>Waiting for live zone data...</td></tr>";
    return;
  }

  table.innerHTML = zones.map(function(zone) {
    const status = normaliseStatus(zone.status);

    return (
      "<tr>" +
      "<td>" + safeValue(zone.node, "Unknown") + "</td>" +
      "<td>" + safeValue(zone.zone, "Unknown") + "</td>" +
      "<td><span class='" + badge(status) + "'>" + status + "</span></td>" +
      "<td>" + safeValue(zone.deviceCount, 0) + "</td>" +
      "<td>" + safeValue(zone.alarmCount, 0) + "</td>" +
      "<td>" + safeValue(zone.faultCount, 0) + "</td>" +
      "<td>" + safeValue(zone.isolatedCount, 0) + "</td>" +
      "</tr>"
    );
  }).join("");
}
function renderFireDevices() {
  const table = document.getElementById("fireDevicesTable");

  if (!table || !latestState) return;

  const devices = Array.isArray(latestState.fireDevices)
    ? latestState.fireDevices
    : [];

  const searchEl = document.getElementById("fireDeviceSearch");
  const statusEl = document.getElementById("fireStatusFilter");

  const search = searchEl
    ? searchEl.value.toLowerCase()
    : "";

  const statusFilter = statusEl
    ? statusEl.value
    : "";

  let filtered = devices.filter(function(device) {
    const status = normaliseStatus(device.status);

    if (statusFilter && status !== statusFilter) {
      return false;
    }

    if (!search) {
      return true;
    }

    return JSON.stringify(device)
      .toLowerCase()
      .includes(search);
  });

  if (filtered.length === 0) {
    table.innerHTML =
      "<tr><td colspan='8'>No matching fire devices.</td></tr>";
    return;
  }

  table.innerHTML = filtered.map(function(device) {
    const status = normaliseStatus(device.status);

    return (
      "<tr class='" + (status === "alarm" ? "alarm-row" : "") + "'>" +
      "<td>" + safeValue(device.node, "Unknown") + "</td>" +
      "<td>" + safeValue(device.loop, "Unknown") + "</td>" +
      "<td>" + safeValue(device.zone, "Unknown") + "</td>" +
      "<td>" + safeValue(device.name, "Unknown") + "</td>" +
      "<td>" + safeValue(device.type, "Unknown") + "</td>" +
      "<td><span class='" + badge(status) + "'>" + status + "</span></td>" +
      "<td>" + safeValue(device.location, "Unknown") + "</td>" +
      "<td>" + safeValue(device.serialNumber, "Unknown") + "</td>" +
      "</tr>"
    );
  }).join("");
}

function updateMusicPage(data) {
  setText("musicPageStatus", data.music || "stopped");
  setText("musicPageSong", data.currentSongNumber || "None");
  setText("musicPageSongId", data.currentSongId || "None");
}

function updateLiftPage(data) {
  setText("liftsPageStatus", data.lifts || "offline");

  const table = document.getElementById("liftTable");

  if (!table) return;

  const lifts = Array.isArray(data.liftData)
    ? data.liftData
    : [];

  if (lifts.length === 0) {
    table.innerHTML =
      "<tr><td colspan='8'>Waiting for lift data...</td></tr>";
    return;
  }

  table.innerHTML = lifts.map(function(lift) {
    return (
      "<tr>" +
      "<td>" + safeValue(lift.name, "Unknown") + "</td>" +
      "<td>" + safeValue(lift.group, "Ungrouped") + "</td>" +
      "<td>" + safeValue(lift.floor, "Unknown") + "</td>" +
      "<td>" + safeValue(lift.direction, "Idle") + "</td>" +
      "<td>" + safeValue(lift.doors, "Unknown") + "</td>" +
      "<td>" + safeValue(lift.status, "Normal") + "</td>" +
      "<td>" + (lift.fireRecall ? "Yes" : "No") + "</td>" +
      "<td>" + safeValue(lift.servedFloors, "Unknown") + "</td>" +
      "</tr>"
    );
  }).join("");
}

function updateAccessPage(data) {
  setText("accessPageStatus", data.access || "offline");

  const table = document.getElementById("accessDoorTable");

  if (!table) return;

  const doors = Array.isArray(data.accessDoors)
    ? data.accessDoors
    : [];

  if (doors.length === 0) {
    table.innerHTML =
      "<tr><td colspan='4'>Waiting for access data...</td></tr>";
    return;
  }

  table.innerHTML = doors.map(function(door) {
    return (
      "<tr>" +
      "<td>" + safeValue(door.name, "Unknown Door") + "</td>" +
      "<td>" + safeValue(door.status, "Unknown") + "</td>" +
      "<td>" + safeValue(door.lock, "Unknown") + "</td>" +
      "<td>" + safeValue(door.mode, "Normal") + "</td>" +
      "</tr>"
    );
  }).join("");
}

function updateControlLocks(data) {
  document.querySelectorAll(".controlBtn").forEach(function(btn) {
    btn.disabled =
      data.controlsLocked ||
      !currentUser ||
      currentUser.role === "operator";
  });
}

async function loadSongs() {
  if (!currentUser) return;

  const list = document.getElementById("songList");

  if (!list) return;

  const oldValue = list.value;

  const res = await fetch("/api/music/songs");

  if (!res.ok) return;

  const data = await res.json();

  list.innerHTML = "";

  const songList = Array.isArray(data.songs)
    ? data.songs
    : [];

  songList.forEach(function(song) {
    const opt = document.createElement("option");

    opt.value = song.number;

    opt.textContent =
      song.number +
      " - " +
      song.id +
      " Pitch: " +
      safeValue(song.pitch, "Default");

    list.appendChild(opt);
  });

  if (oldValue) {
    list.value = oldValue;
  }
}

async function loadEvents() {
  if (!currentUser) return;

  const res = await fetch("/api/events");

  if (!res.ok) return;

  const data = await res.json();

  const events = Array.isArray(data.events)
    ? data.events
    : [];

  const html = events.map(function(e) {
    return (
      "<div class='event'>" +
      "<b>" + e.type + "</b><br>" +
      new Date(e.created_at).toLocaleString() +
      "</div>"
    );
  }).join("");

  setHTML("events", html || "No events yet.");
  setHTML("eventsDash", html || "No events yet.");
}

async function sendCommand(command, songNumber) {
  const res = await fetch("/api/music/command", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      command,
      songNumber
    })
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error || "Music command failed");
    return;
  }

  await loadState();
  await loadEvents();
}

async function sendAccess(command, value) {
  const res = await fetch("/api/access/command", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      command,
      value
    })
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error || "Access command failed");
    return;
  }

  await loadState();
  await loadEvents();
}

function playSelected() {
  const list = document.getElementById("songList");

  if (!list) return;

  const songNumber = Number(list.value);

  sendCommand("play_song", songNumber);
}

checkLogin();
updateClock();

setInterval(updateClock, 1000);
setInterval(loadState, 1000);
setInterval(loadEvents, 5000);
</script>

</body>
</html>
  `);
});
app.get("/api/music/songs", requireLogin, (req, res) => {
  res.json({ songs });
});

app.post("/api/music/command", requireRole("supervisor", "administrator"), async (req, res) => {
  if (bmsState.controlsLocked) {
    return res.status(423).json({ error: "Controls locked by fire alarm" });
  }

  latestCommand = {
    id: Date.now(),
    command: req.body.command || "none",
    songNumber: req.body.songNumber || null,
    controlsLocked: bmsState.controlsLocked
  };

  await logEvent("music_command", {
    user: req.session.user.username,
    role: req.session.user.role,
    command: latestCommand
  });

  res.json({ ok: true, command: latestCommand });
});

app.get("/api/roblox/music/command", (req, res) => {
  if (!checkSecret(req, res)) return;

  res.json(latestCommand);
});

app.post("/api/roblox/music/songs", async (req, res) => {
  if (!checkSecret(req, res)) return;

  songs = Array.isArray(req.body.songs)
    ? req.body.songs
    : [];

  bmsState.lastRobloxUpdate = new Date().toISOString();

  await logEvent("song_list_update", {
    count: songs.length
  });

  res.json({
    ok: true,
    count: songs.length
  });
});

app.post("/api/roblox/music/state", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.music =
    req.body.state ||
    bmsState.music;

  bmsState.currentSongNumber =
    req.body.currentSongNumber ||
    null;

  bmsState.currentSongId =
    req.body.currentSongId ||
    null;

  bmsState.lastRobloxUpdate =
    new Date().toISOString();

  await logEvent("music_state", {
    state: bmsState.music,
    currentSongNumber: bmsState.currentSongNumber,
    currentSongId: bmsState.currentSongId
  });

  res.json({
    ok: true,
    state: bmsState
  });
});

app.post("/api/access/command", requireRole("supervisor", "administrator"), async (req, res) => {
  if (bmsState.controlsLocked) {
    return res.status(423).json({ error: "Controls locked by fire alarm" });
  }

  latestAccessCommand = {
    id: Date.now(),
    command: req.body.command || "none",
    value: req.body.value || null
  };

  await logEvent("access_command", {
    user: req.session.user.username,
    role: req.session.user.role,
    command: latestAccessCommand
  });

  res.json({
    ok: true,
    command: latestAccessCommand
  });
});

app.get("/api/roblox/access/command", (req, res) => {
  if (!checkSecret(req, res)) return;

  res.json(latestAccessCommand);
});

app.post("/api/roblox/access/state", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.access =
    req.body.access ||
    req.body.state ||
    "online";

  bmsState.accessDoors =
    Array.isArray(req.body.doors)
      ? req.body.doors
      : [];

  bmsState.lastRobloxUpdate =
    new Date().toISOString();

  await logEvent("access_state", {
    access: bmsState.access,
    doors: bmsState.accessDoors.length
  });

  res.json({
    ok: true,
    state: bmsState
  });
});

app.post("/api/roblox/fire/live", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.fireLive =
    req.body.fireLive ||
    "online";

  bmsState.fireDevices =
    Array.isArray(req.body.devices)
      ? req.body.devices
      : [];

  bmsState.fireZones =
    Array.isArray(req.body.zones)
      ? req.body.zones
      : [];

  bmsState.fireNodes =
    Array.isArray(req.body.nodes)
      ? req.body.nodes
      : deriveNodesFromFireDevices(bmsState.fireDevices);

  bmsState.lastRobloxUpdate =
    new Date().toISOString();

  await logEvent("fire_live_update", {
    devices: bmsState.fireDevices.length,
    zones: bmsState.fireZones.length,
    nodes: bmsState.fireNodes.length
  });

  res.json({
    ok: true,
    state: bmsState
  });
});

app.post("/api/roblox/fire/active", async (req, res) => {
  if (!checkSecret(req, res)) return;

  const fireEvent = {
    eventType: req.body.eventType || "Fire",
    deviceName: req.body.deviceName || "Unknown Device",
    device: req.body.device || "Unknown",
    location: req.body.location || "Unknown",
    zone: req.body.zone || "Unknown",
    node: req.body.node || "Unknown",
    loop: req.body.loop || "Unknown",
    serialNumber: req.body.serialNumber || "Unknown",
    origin: req.body.origin || "Roblox",
    time: req.body.time || new Date().toLocaleTimeString()
  };

  bmsState.fire = "alarm";
  bmsState.controlsLocked = true;
  bmsState.music = "fire_locked";
  bmsState.activeFire = fireEvent;
  bmsState.lastRobloxUpdate = new Date().toISOString();

  bmsState.fireEvents.unshift(fireEvent);
  bmsState.fireEvents = bmsState.fireEvents.slice(0, 50);

  latestCommand = {
    id: Date.now(),
    command: "none",
    songNumber: null,
    controlsLocked: true
  };

  await logEvent("fire_active", fireEvent);

  res.json({
    ok: true,
    state: bmsState
  });
});

app.post("/api/roblox/fire/reset", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.fire = "normal";
  bmsState.controlsLocked = false;
  bmsState.activeFire = null;
  bmsState.fireEvents = [];
  bmsState.lastRobloxUpdate = new Date().toISOString();

  latestCommand = {
    id: Date.now(),
    command: "none",
    songNumber: null,
    controlsLocked: false
  };

  await logEvent("fire_reset", req.body);

  res.json({
    ok: true,
    state: bmsState
  });
});
app.post("/api/roblox/lifts/state", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.lifts =
    req.body.lifts ||
    req.body.state ||
    "online";

  bmsState.liftData =
    Array.isArray(req.body.liftData)
      ? req.body.liftData
      : [];

  bmsState.lastRobloxUpdate =
    new Date().toISOString();

  await logEvent("lifts_state", {
    lifts: bmsState.lifts,
    count: bmsState.liftData.length
  });

  res.json({
    ok: true,
    state: bmsState
  });
});

app.get("/api/debug/reset-fire", async (req, res) => {
  bmsState.fire = "normal";
  bmsState.fireLive = "offline";
  bmsState.controlsLocked = false;
  bmsState.activeFire = null;
  bmsState.fireEvents = [];
  bmsState.fireDevices = [];
  bmsState.fireZones = [];
  bmsState.fireNodes = [];

  bmsState.music = "stopped";
  bmsState.lifts = "offline";
  bmsState.access = "offline";

  latestCommand = {
    id: Date.now(),
    command: "none",
    songNumber: null,
    controlsLocked: false
  };

  await logEvent("debug_reset_fire", {
    source: "manual_debug_endpoint"
  });

  res.json({
    ok: true,
    message: "BMS fire/debug state reset.",
    state: bmsState
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "Whitford BMS",
    version: bmsState.version,
    time: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "Whitford BMS",
    version: bmsState.version,
    fire: bmsState.fire,
    music: bmsState.music,
    lifts: bmsState.lifts,
    access: bmsState.access,
    lastRobloxUpdate: bmsState.lastRobloxUpdate
  });
});

function deriveNodesFromFireDevices(devices) {
  const nodeMap = {};

  devices.forEach(function(device) {
    const nodeName =
      device.node ||
      "Unknown";

    if (!nodeMap[nodeName]) {
      nodeMap[nodeName] = {
        node: nodeName,
        deviceCount: 0,
        alarmCount: 0,
        faultCount: 0,
        isolatedCount: 0
      };
    }

    nodeMap[nodeName].deviceCount += 1;

    const status = String(device.status || "normal").toLowerCase();

    if (status === "alarm") {
      nodeMap[nodeName].alarmCount += 1;
    } else if (status === "fault") {
      nodeMap[nodeName].faultCount += 1;
    } else if (status === "isolated" || status === "disabled") {
      nodeMap[nodeName].isolatedCount += 1;
    }
  });

  return Object.values(nodeMap);
}

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log("Whitford BMS v2 running on port", PORT);
    });
  })
  .catch((err) => {
    console.error("Failed to start Whitford BMS:", err);
    process.exit(1);
  });
