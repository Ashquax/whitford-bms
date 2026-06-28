const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);

const app = express();

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
    secure: true,
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

app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Whitford BMS</title>
<style>
body { font-family: Arial; background:#101018; color:white; padding:20px; }
.card { background:#1e1e2e; padding:15px; margin:10px 0; border-radius:10px; }
button { padding:10px; margin:5px; cursor:pointer; }
button:disabled { opacity:0.4; cursor:not-allowed; }
input, select { padding:10px; margin:5px; }
.alarm { color:#ff4444; font-weight:bold; }
.normal { color:#44ff88; font-weight:bold; }
.hidden { display:none; }
</style>
</head>
<body>

<h1>Whitford Shopping Centre BMS</h1>

<div id="loginBox" class="card">
  <h2>Login</h2>
  <input id="username" placeholder="Username">
  <input id="password" placeholder="Password" type="password">
  <button onclick="login()">Login</button>
  <p id="loginMsg"></p>
</div>

<div id="appBox" class="hidden">
  <div class="card">
    <h2>User</h2>
    <p>Logged in as: <span id="user"></span></p>
    <p>Role: <span id="role"></span></p>
    <button onclick="logout()">Logout</button>
  </div>

  <div class="card">
    <h2>System Status</h2>
    <p>Fire: <span id="fire"></span></p>
    <p>Controls Locked: <span id="locked"></span></p>
    <p>Music: <span id="music"></span></p>
    <p>Current Song: <span id="song"></span></p>
    <p>Lifts: <span id="lifts"></span></p>
    <p>Access: <span id="access"></span></p>
  </div>

  <div class="card">
    <h2>Music Control</h2>
    <button class="controlBtn" onclick="sendCommand('play')">Play</button>
    <button class="controlBtn" onclick="sendCommand('pause')">Pause</button>
    <button class="controlBtn" onclick="sendCommand('stop')">Stop</button>
    <br><br>
    <select id="songList"></select>
    <button class="controlBtn" onclick="playSelected()">Play Selected Song</button>
  </div>

  <div class="card">
    <h2>Event Log</h2>
    <div id="events"></div>
  </div>
</div>

<script>
let currentUser = null;

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
    document.getElementById("loginBox").classList.remove("hidden");
    document.getElementById("appBox").classList.add("hidden");
  }
}

async function login() {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      username: document.getElementById("username").value,
      password: document.getElementById("password").value
    })
  });

  const data = await res.json();

  if (!res.ok) {
    document.getElementById("loginMsg").textContent = data.error || "Login failed";
    return;
  }

  checkLogin();
}

async function logout() {
  await fetch("/api/auth/logout", { method: "POST" });
  currentUser = null;
  checkLogin();
}

async function loadState() {
  if (!currentUser) return;

  const res = await fetch("/api/state");
  const data = await res.json();

  document.getElementById("fire").textContent = data.fire;
  document.getElementById("fire").className = data.fire === "alarm" ? "alarm" : "normal";
  document.getElementById("locked").textContent = data.controlsLocked;
  document.getElementById("music").textContent = data.music;
  document.getElementById("song").textContent = data.currentSongNumber || "None";
  document.getElementById("lifts").textContent = data.lifts;
  document.getElementById("access").textContent = data.access;

  document.querySelectorAll(".controlBtn").forEach(btn => {
    btn.disabled = data.controlsLocked || currentUser.role === "operator";
  });
}

async function loadSongs() {
  if (!currentUser) return;

  const res = await fetch("/api/music/songs");
  const data = await res.json();

  const list = document.getElementById("songList");
  list.innerHTML = "";

  data.songs.forEach(song => {
    const opt = document.createElement("option");
    opt.value = song.number;
    opt.textContent = song.number + " - " + song.id + " Pitch: " + song.pitch;
    list.appendChild(opt);
  });
}

async function loadEvents() {
  if (!currentUser) return;

  const res = await fetch("/api/events");
  const data = await res.json();

  document.getElementById("events").innerHTML = data.events.map(e => {
    return "<p><b>" + e.type + "</b> - " + new Date(e.created_at).toLocaleString() + "</p>";
  }).join("");
}

async function sendCommand(command, songNumber) {
  const res = await fetch("/api/music/command", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ command, songNumber })
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error || "Command failed");
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
setInterval(loadSongs, 10000);
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
  const result = await pool.query(
    "SELECT * FROM event_log ORDER BY id DESC LIMIT 50"
  );

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

initDb().then(() => {
  app.listen(PORT, () => {
    console.log("Whitford BMS running on port", PORT);
  });
});
