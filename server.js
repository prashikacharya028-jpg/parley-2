// server.js — Photo upload server (Express + Multer)
// Run:
//   npm init -y
//   npm install express multer cors
//   node server.js

const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, "uploads");
const DB_FILE = path.join(__dirname, "photos.json");
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
const MAX_FILES_PER_REQUEST = 10;
const ALLOWED_TYPES = ["image/jpeg", "image/png", "image/webp", "image/gif"];

// ---------- Setup ----------
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "[]");

const readDb = () => JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
const writeDb = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));

// ---------- Multer config ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${crypto.randomUUID()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES_PER_REQUEST },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_TYPES.includes(file.mimetype)) return cb(null, true);
    cb(new Error("Only JPEG, PNG, WebP and GIF images are allowed"));
  },
});

// ---------- App ----------
const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(UPLOAD_DIR));

// Add photo(s) — form-data field name: "photos" (one or many)
app.post("/api/photos", upload.array("photos", MAX_FILES_PER_REQUEST), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: "No photo uploaded. Use field name 'photos'." });
  }

  const db = readDb();
  const added = req.files.map((f) => ({
    id: path.parse(f.filename).name,
    filename: f.filename,
    originalName: f.originalname,
    mimeType: f.mimetype,
    size: f.size,
    caption: req.body.caption || "",
    url: `${req.protocol}://${req.get("host")}/uploads/${f.filename}`,
    createdAt: new Date().toISOString(),
  }));

  db.push(...added);
  writeDb(db);
  res.status(201).json({ message: "Photo(s) added", photos: added });
});

// List all photos
app.get("/api/photos", (req, res) => {
  res.json(readDb());
});

// Get one photo's details
app.get("/api/photos/:id", (req, res) => {
  const photo = readDb().find((p) => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: "Photo not found" });
  res.json(photo);
});

// Update caption
app.patch("/api/photos/:id", (req, res) => {
  const db = readDb();
  const photo = db.find((p) => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: "Photo not found" });
  if (typeof req.body.caption === "string") photo.caption = req.body.caption;
  writeDb(db);
  res.json(photo);
});

// Delete a photo
app.delete("/api/photos/:id", (req, res) => {
  const db = readDb();
  const index = db.findIndex((p) => p.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: "Photo not found" });

  const [removed] = db.splice(index, 1);
  fs.unlink(path.join(UPLOAD_DIR, removed.filename), () => {});
  writeDb(db);
  res.json({ message: "Photo deleted" });
});

// ---------- Error handling ----------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const msg =
      err.code === "LIMIT_FILE_SIZE"
        ? `File too large (max ${MAX_FILE_SIZE / 1024 / 1024} MB)`
        : err.message;
    return res.status(400).json({ error: msg });
  }
  if (err) return res.status(400).json({ error: err.message });
  next();
});

app.listen(PORT, () => console.log(`Photo server running on http://localhost:${PORT}`));
