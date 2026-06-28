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

let bmsState = {
  fire: "normal",
  controlsLocked: false,
  music: "stopped",
  currentSongNumber: null,
  currentSongId: null,
  lifts: "normal",
  access: "normal"
};

let songs = [];

let latestCommand = {
  id: 0,
  command: "none",
  songNumber: null,
  controlsLocked: false
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
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
    if (!roles.includes(req.session.user.role)) return res.status(403).json({ error: "No permission" });
    next();
  };
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS event_log (
      id SERIAL PRIMARY KEY,
      type TEXT NOT NULL,
      data JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('operator', 'supervisor', 'administrator')),
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
    return res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Setup Complete</title>
<style>
body { font-family:Arial; background:#f4f5f7; padding:40px; }
a { color:#e20015; }
</style>
</head>
<body>
<h1>Setup already completed</h1>
<p>The administrator account has already been created.</p>
<a href="/">Go to login</a>
</body>
</html>
    `);
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Whitford BMS Setup</title>
<style>
body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f2f3f5; color:#1f2933; }
.topbar { height:6px; background:#e20015; }
.container { max-width:460px; margin:80px auto; background:white; border-radius:4px; box-shadow:0 8px 25px rgba(0,0,0,0.12); padding:34px; }
.brand { font-size:24px; font-weight:bold; margin-bottom:4px; }
.sub { color:#6b7280; margin-bottom:30px; }
input { width:100%; box-sizing:border-box; padding:13px; margin:8px 0 16px; border:1px solid #c8ccd2; border-radius:3px; }
button { width:100%; background:#e20015; color:white; border:0; padding:14px; font-weight:bold; cursor:pointer; border-radius:3px; }
button:hover { background:#b80012; }
.msg { margin-top:15px; color:#e20015; }
</style>
</head>
<body>
<div class="topbar"></div>
<div class="container">
  <div class="brand">Whitford BMS</div>
  <div class="sub">Initial administrator setup</div>
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

app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Whitford Building Management System</title>
<style>
* { box-sizing:border-box; }
body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#eef0f3; color:#1f2933; }
.bosch-strip { height:6px; background:#e20015; }
.header { height:64px; background:white; border-bottom:1px solid #d8dce2; display:flex; align-items:center; justify-content:space-between; padding:0 24px; }
.logo { font-size:22px; font-weight:bold; }
.logo span { color:#e20015; }
.userbar { color:#6b7280; font-size:14px; }
.layout { display:flex; height:calc(100vh - 70px); }
.sidebar { width:245px; background:#26313f; color:white; padding-top:20px; }
.nav { padding:15px 24px; border-left:4px solid transparent; cursor:pointer; }
.nav:hover, .nav.active { background:#1d2631; border-left-color:#e20015; }
.main { flex:1; padding:24px; overflow:auto; }
.card { background:white; border:1px solid #d8dce2; border-radius:4px; padding:20px; margin-bottom:18px; }
.grid { display:grid; grid-template-columns:repeat(4, 1fr); gap:18px; }
.status-card { background:white; border-top:5px solid #9ca3af; padding:20px; min-height:120px; }
.status-card.alarm { border-top-color:#e20015; }
.status-card.ok { border-top-color:#00884a; }
.status-title { font-size:14px; color:#6b7280; }
.status-value { font-size:28px; margin-top:12px; font-weight:bold; }
button { background:#e20015; color:white; border:0; padding:11px 16px; margin:5px; cursor:pointer; border-radius:3px; font-weight:bold; }
button:disabled { background:#9ca3af; cursor:not-allowed; }
input, select { padding:11px; border:1px solid #c8ccd2; border-radius:3px; min-width:260px; }
.login-box { max-width:420px; margin:90px auto; background:white; padding:34px; box-shadow:0 8px 25px rgba(0,0,0,0.12); }
.hidden { display:none; }
.alarm-text { color:#e20015; font-weight:bold; }
.good-text { color:#00884a; font-weight:bold; }
.event { padding:10px; border-bottom:1px solid #e5e7eb; font-size:14px; }
.page-title { margin-top:0; }
.badge { display:inline-block; padding:5px 10px; border-radius:20px; font-size:13px; font-weight:bold; }
.badge-ok { background:#d9f7e8; color:#00884a; }
.badge-alarm { background:#ffe1e4; color:#e20015; }
.table { width:100%; border-collapse:collapse; }
.table th, .table td { text-align:left; padding:10px; border-bottom:1px solid #e5e7eb; }
.small { color:#6b7280; font-size:13px; }
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
      <span id="user"></span> | <span id="role"></span>
      <button onclick="logout()">Logout</button>
    </div>
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
          <p>Controls Locked: <span id="firePageLocked"></span></p>
          <p class="small">Fire alarm is monitored from Roblox. BMS controls lock automatically during alarm.</p>
        </div>
      </div>

      <div id="page-music" class="page hidden">
        <h1 class="page-title">Music Control</h1>
        <div class="card">
          <h2>Playback</h2>
          <p>Status: <span id="musicPageStatus"></span></p>
          <p>Current Song: <span id="musicPageSong"></span></p>
          <button class="controlBtn" onclick="sendCommand('play')">Play</button>
          <button class="controlBtn" onclick="sendCommand('pause')">Pause</button>
          <button class="controlBtn" onclick="sendCommand('stop')">Stop</button>
        </div>

        <div class="card">
          <h2>Song Library From Roblox</h2>
          <select id="songList"></select>
          <button class="controlBtn" onclick="playSelected()">Play Selected Song</button>
          <p class="small">Songs are uploaded from your Roblox MusicSettings module. The list no longer auto-refreshes, so it will not jump back to song 1.</p>
        </div>
      </div>

      <div id="page-lifts" class="page hidden">
        <h1 class="page-title">Lift Monitoring</h1>
        <div class="card">
          <h2>Lift System</h2>
          <p>Status: <span id="liftsPageStatus"></span></p>
        </div>
      </div>

      <div id="page-access" class="page hidden">
        <h1 class="page-title">Access Control</h1>
        <div class="card">
          <h2>Door System</h2>
          <p>Status: <span id="accessPageStatus"></span></p>
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
          <p><b>Supervisor:</b> Music control</p>
          <p><b>Administrator:</b> Full access</p>
        </div>
      </div>

    </div>
  </div>
</div>

<script>
let currentUser = null;

function showPage(page, el) {
  document.querySelectorAll(".page").forEach(p => p.classList.add("hidden"));
  document.getElementById("page-" + page).classList.remove("hidden");

  document.querySelectorAll(".nav").forEach(n => n.classList.remove("active"));
  el.classList.add("active");

  if (page === "music") {
    loadSongs();
  }
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
    loadState();
    loadSongs();
    loadEvents();
  } else {
    currentUser = null;
    document.getElementById("loginBox").classList.remove("hidden");
    document.getElementById("appBox").classList.add("hidden");
  }
}

async function login() {
  const res = await fetch("/api/auth/login", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      username:document.getElementById("username").value,
      password:document.getElementById("password").value
    })
  });

  const data = await res.json();

  if (!res.ok) {
    document.getElementById("loginMsg").textContent = data.error || "Login failed";
    return;
  }

  await checkLogin();
}

async function logout() {
  await fetch("/api/auth/logout", { method:"POST" });
  currentUser = null;
  checkLogin();
}

async function loadState() {
  if (!currentUser) return;

  const res = await fetch("/api/state");
  const data = await res.json();

  document.getElementById("fire").textContent = data.fire;
  document.getElementById("music").textContent = data.music;
  document.getElementById("lifts").textContent = data.lifts;
  document.getElementById("access").textContent = data.access;
  document.getElementById("locked").textContent = data.controlsLocked;
  document.getElementById("song").textContent = data.currentSongNumber || "None";

  document.getElementById("firePageStatus").innerHTML = data.fire === "alarm"
    ? "<span class='badge badge-alarm'>ALARM</span>"
    : "<span class='badge badge-ok'>NORMAL</span>";

  document.getElementById("firePageLocked").textContent = data.controlsLocked;
  document.getElementById("musicPageStatus").textContent = data.music;
  document.getElementById("musicPageSong").textContent = data.currentSongNumber || "None";
  document.getElementById("liftsPageStatus").textContent = data.lifts;
  document.getElementById("accessPageStatus").textContent = data.access;

  const fireCard = document.getElementById("fireCard");
  fireCard.className = data.fire === "alarm" ? "status-card alarm" : "status-card ok";

  document.querySelectorAll(".controlBtn").forEach(btn => {
    btn.disabled = data.controlsLocked || currentUser.role === "operator";
  });
}

async function loadSongs() {
  if (!currentUser) return;

  const list = document.getElementById("songList");
  const oldValue = list.value;

  const res = await fetch("/api/music/songs");
  const data = await res.json();

  list.innerHTML = "";

  data.songs.forEach(song => {
    const opt = document.createElement("option");
    opt.value = song.number;
    opt.textContent = song.number + " - " + song.id + " Pitch: " + song.pitch;
    list.appendChild(opt);
  });

  if (oldValue) {
    list.value = oldValue;
  }
}

async function loadEvents() {
  if (!currentUser) return;

  const res = await fetch("/api/events");
  const data = await res.json();

  const html = data.events.map(e => {
    return "<div class='event'><b>" + e.type + "</b><br>" + new Date(e.created_at).toLocaleString() + "</div>";
  }).join("");

  document.getElementById("events").innerHTML = html;
  document.getElementById("eventsDash").innerHTML = html;
}

async function sendCommand(command, songNumber) {
  const res = await fetch("/api/music/command", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({ command, songNumber })
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error || "Command failed");
    return;
  }

  loadState();
  loadEvents();
}

function playSelected() {
  const num = document.getElementById("songList").value;
  sendCommand("play_song", Number(num));
}

checkLogin();

setInterval(loadState, 1000);
setInterval(loadEvents, 5000);
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

  const passwordHash = await bcrypt.hash(req.body.password, 12);

  await pool.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)",
    [req.body.username, passwordHash, "administrator"]
  );

  res.json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
  const user = result.rows[0];

  if (!user) return res.status(401).json({ error: "Invalid username or password" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid username or password" });

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role
  };

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

app.get("/api/music/songs", requireLogin, (req, res) => {
  res.json({ songs });
});

app.get("/api/events", requireLogin, async (req, res) => {
  const result = await pool.query("SELECT * FROM event_log ORDER BY id DESC LIMIT 50");
  res.json({ events: result.rows });
});

app.post("/api/music/command", requireRole("supervisor", "administrator"), async (req, res) => {
  if (bmsState.controlsLocked) {
    return res.status(423).json({ error: "Controls locked by fire alarm" });
  }

  latestCommand = {
    id: Date.now(),
    command: req.body.command,
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

  songs = req.body.songs || [];

  await logEvent("song_list_update", { count: songs.length });
  res.json({ ok: true, count: songs.length });
});

app.post("/api/roblox/music/state", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.music = req.body.state || bmsState.music;
  bmsState.currentSongNumber = req.body.currentSongNumber || null;
  bmsState.currentSongId = req.body.currentSongId || null;

  await logEvent("music_state", req.body);
  res.json({ ok: true, state: bmsState });
});

app.post("/api/roblox/fire/active", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.fire = "alarm";
  bmsState.controlsLocked = true;
  bmsState.music = "fire_locked";

  latestCommand = {
    id: Date.now(),
    command: "none",
    songNumber: null,
    controlsLocked: true
  };

  await logEvent("fire_active", req.body);
  res.json({ ok: true, state: bmsState });
});

app.post("/api/roblox/fire/reset", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.fire = "normal";
  bmsState.controlsLocked = false;

  latestCommand = {
    id: Date.now(),
    command: "none",
    songNumber: null,
    controlsLocked: false
  };

  await logEvent("fire_reset", req.body);
  res.json({ ok: true, state: bmsState });
});

app.post("/api/roblox/lifts/state", async (req, res) => {
  if (!checkSecret(req, res)) return;

  bmsState.lifts = req.body.lifts || "normal";

  await logEvent("lifts_state", req.body);
  res.json({ ok: true, state: bmsState });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log("Whitford BMS running on port", PORT);
    });
  })
  .catch((err) => {
    console.error("Failed to start BMS:", err);
    process.exit(1);
  });
