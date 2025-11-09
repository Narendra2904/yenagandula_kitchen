// api/server.js
const express = require("express");
const serverless = require("serverless-http");
const cors = require("cors");
const fs = require("fs-extra");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Config ---
const SECRET = process.env.JWT_SECRET || "demo-secret";
const USERS_FILE = path.join("/tmp", "users.json");

// --- Helpers ---
async function readUsers() {
  try {
    if (await fs.pathExists(USERS_FILE)) return fs.readJSON(USERS_FILE);
  } catch {}
  return {};
}
async function writeUsers(users) {
  try {
    await fs.outputJSON(USERS_FILE, users, { spaces: 2 });
  } catch (err) {
    console.error("writeUsers error", err);
  }
}

// --- Routes ---
app.get("/api/health", (_, res) => res.json({ ok: true }));

app.post("/api/register", async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  const users = await readUsers();
  if (users[username]) return res.status(400).json({ error: "User exists" });

  const hash = await bcrypt.hash(password, 10);
  users[username] = { username, email, password: hash, createdAt: Date.now() };
  await writeUsers(users);

  res.json({ success: true, message: "Registered successfully" });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  const users = await readUsers();
  const user = users[username];
  if (!user) return res.status(400).json({ error: "Invalid user" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ username }, SECRET, { expiresIn: "7d" });
  res.json({ success: true, token });
});

app.get("/api/me", async (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const data = jwt.verify(token, SECRET);
    res.json({ user: data.username });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

module.exports = app;
module.exports.handler = serverless(app);
