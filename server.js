const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 8080;
const SECRET = process.env.BMS_SECRET || "CHANGE_THIS_SECRET";

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

let bmsState = {
    fire: "normal",
    controlsLocked: false,
    music: "stopped",
    currentSongNumber: null,
    currentSongId: null,
    lifts: "normal",
    access: "normal",
};

let songs = [];
let latestCommand = {
    id: 0,
    command: "none",
    songNumber: null,
    controlsLocked: false,
};

function checkSecret(req, res) {
    const secret = req.body.secret || req.query.secret;
    if (secret !== SECRET) {
        res.status(403).json({ error: "Bad secret" });
        return false;
    }
    return true;
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
<title>Roblox BMS</title>
<style>
body { font-family: Arial; background:#111; color:white; padding:20px; }
.card { background:#222; padding:15px; margin:10px 0; border-radius:10px; }
button { padding:10px; margin:5px; cursor:pointer; }
button:disabled { opacity:0.4; cursor:not-allowed; }
select { padding:10px; }
.alarm { color:#ff4444; font-weight:bold; }
.normal { color:#44ff88; font-weight:bold; }
</style>
</head>
<body>
<h1>Building Management System</h1>

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
  <button onclick="sendCommand('play')">Play</button>
  <button onclick="sendCommand('pause')">Pause</button>
  <button onclick="sendCommand('stop')">Stop</button>
  <br><br>
  <select id="songList"></select>
  <button onclick="playSelected()">Play Selected Song</button>
</div>

<script>
async function loadState() {
  const res = await fetch("/api/state");
  const data = await res.json();

  document.getElementById("fire").textContent = data.fire;
  document.getElementById("fire").className = data.fire === "alarm" ? "alarm" : "normal";
  document.getElementById("locked").textContent = data.controlsLocked;
  document.getElementById("music").textContent = data.music;
  document.getElementById("song").textContent = data.currentSongNumber || "None";
  document.getElementById("lifts").textContent = data.lifts;
  document.getElementById("access").textContent = data.access;

  document.querySelectorAll("button").forEach(btn => {
    btn.disabled = data.controlsLocked;
  });
}

async function loadSongs() {
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

async function sendCommand(command, songNumber) {
  await fetch("/api/music/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      secret: prompt("Enter BMS secret"),
      command,
      songNumber
    })
  });

  loadState();
}

function playSelected() {
  const num = document.getElementById("songList").value;
  sendCommand("play_song", Number(num));
}

loadState();
loadSongs();
setInterval(loadState, 1000);
setInterval(loadSongs, 10000);
</script>
</body>
</html>
  `);
});

app.get("/api/state", (req, res) => {
    res.json(bmsState);
});

app.get("/api/music/songs", (req, res) => {
    res.json({ songs });
});

app.post("/api/music/command", async (req, res) => {
    if (!checkSecret(req, res)) return;

    if (bmsState.controlsLocked) {
        return res.status(423).json({ error: "Controls locked by fire alarm" });
    }

    latestCommand = {
        id: Date.now(),
        command: req.body.command,
        songNumber: req.body.songNumber || null,
        controlsLocked: bmsState.controlsLocked,
    };

    await logEvent("music_command", latestCommand);
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
        controlsLocked: true,
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
        controlsLocked: false,
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
        console.log("BMS running on port", PORT);
    });
});