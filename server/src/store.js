// Scan history. Uses MongoDB when MONGODB_URI is set; otherwise an in-memory ring buffer
// so the app still works with zero infrastructure (e.g. on a free hosting tier).
import mongoose from 'mongoose';

const ScanSchema = new mongoose.Schema({
  repo: { type: String, index: true },
  webUrl: String,
  branch: String,
  commit: String,
  method: String,
  score: Number,
  grade: String,
  counts: { critical: Number, high: Number, medium: Number, low: Number },
  total: Number,
  stats: { filesScanned: Number, filesSkipped: Number, bytesScanned: Number },
  durationMs: Number,
  // Findings are stored masked only — never the raw secret.
  findings: [{
    ruleId: String, name: String, provider: String, severity: String, placeholder: Boolean,
    file: String, line: Number, column: Number, masked: String, context: String, detector: String, entropy: Number, testOrDocs: Boolean,
    snippet: [{ n: Number, text: String }],
    occurrences: [{ file: String, line: Number }],
  }],
  gitignore: String,
  rotation: mongoose.Schema.Types.Mixed,
}, { timestamps: true });

let Scan = null;
let mode = 'memory';
const memory = [];
const MEMORY_LIMIT = 50;

export async function initStore() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.log('[store] MONGODB_URI not set — using in-memory history');
    return mode;
  }
  try {
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 });
    Scan = mongoose.model('Scan', ScanSchema);
    mode = 'mongodb';
    console.log('[store] connected to MongoDB');
  } catch (err) {
    console.warn('[store] MongoDB connection failed, falling back to memory:', err.message);
  }
  return mode;
}

export function storeMode() { return mode; }

export async function saveScan(doc) {
  if (mode === 'mongodb') {
    const saved = await Scan.create(doc);
    return saved.toObject({ versionKey: false });
  }
  const rec = { _id: String(Date.now()) + Math.random().toString(36).slice(2, 8), createdAt: new Date(), ...doc };
  memory.unshift(rec);
  if (memory.length > MEMORY_LIMIT) memory.pop();
  return rec;
}

export async function listScans(limit = 20) {
  if (mode === 'mongodb') {
    return Scan.find({}, { findings: 0, rotation: 0, gitignore: 0 }).sort({ createdAt: -1 }).limit(limit).lean();
  }
  return memory.slice(0, limit).map(({ findings, rotation, gitignore, ...rest }) => rest);
}

export async function getScan(id) {
  if (mode === 'mongodb') {
    if (!mongoose.isValidObjectId(id)) return null;
    return Scan.findById(id).lean();
  }
  return memory.find((s) => s._id === id) || null;
}
