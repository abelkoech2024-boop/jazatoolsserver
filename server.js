const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const PDFDocument = require("pdfkit");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BRAND_NAME = process.env.BRAND_NAME || "JazaTools";
const SWIFTWALLET_BASE_URL = (process.env.SWIFTWALLET_BASE_URL || "https://swiftwallet.co.ke/v3").replace(/\/$/, "");
const API_KEY = process.env.SWIFTWALLET_API_KEY || "";
const CALLBACK_URL = process.env.SWIFTWALLET_CALLBACK_URL || `${process.env.PUBLIC_BASE_URL || "https://backendserver.onrender.com"}/api/payments/webhook`;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || (process.env.NODE_ENV === "production" ? "" : "3462");
const STORAGE_DIR = path.join(__dirname, "storage");
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : undefined }) : null;
const sessions = new Map();
const memory = {
  services: [],
  users: [],
  orders: [],
  attempts: [],
  transactions: [],
  files: [],
  referrals: [],
  savedTools: [],
  settings: { siteName: BRAND_NAME, tagline: "Professional work, made local.", supportWhatsApp: "+254718369524", currency: "KES", maintenanceMode: false, downloadExpiryDays: 30 },
  activity: []
};

const seedServices = [
  ["cv-builder", "CV Builder", "Career", "Turn your experience into a clear, confident CV.", 250, "doc", true, true, true, true, "cv"],
  ["invoice-generator", "Invoice Generator", "Business", "Professional invoices with totals, tax and your details.", 100, "doc", true, true, true, true, "invoice"],
  ["receipt-generator", "Receipt Generator", "Business", "Issue a neat receipt in under a minute.", 80, "doc", true, false, true, false, "receipt"],
  ["quotation-generator", "Quotation Generator", "Business", "Send a quote that makes the next step easy.", 100, "doc", true, false, true, true, "quotation"],
  ["business-poster", "Business Poster", "Design", "Announce your offer with real stopping power.", 250, "image", true, true, true, false, "poster"],
  ["company-stamp", "Company Stamp", "Business", "A crisp business graphic for documents and packaging.", 150, "grid", true, false, true, true, "stamp"],
  ["passport-photo", "Passport Photo", "Photos", "Clean, correctly-sized photos for official forms.", 120, "image", true, false, false, false, "photo"],
  ["business-card", "Business Card", "Business", "Your name, number and next opportunity — together.", 180, "grid", true, false, true, true, "card"],
  ["restaurant-menu", "Restaurant Menu", "Food", "A menu that is easy to scan and hard to forget.", 220, "doc", true, false, false, true, "menu"],
  ["invitation-maker", "Invitation Maker", "Events", "Make the important date feel like an occasion.", 200, "spark", true, false, false, false, "invitation"],
  ["certificate-maker", "Certificate Maker", "Education", "Recognise good work with something worth keeping.", 150, "doc", true, false, false, false, "certificate"],
  ["qr-code-generator", "QR Code Generator", "Services", "Send people straight to your link or location.", 80, "grid", true, false, false, false, "qr"],
  ["ai-product-description", "AI Product Description", "AI", "A sharper description for your next product listing.", 100, "spark", true, false, false, false, "ai"]
];

function now() { return new Date().toISOString(); }
function id(prefix = "") { return `${prefix}${crypto.randomBytes(10).toString("hex")}`; }
function normalizePhone(value) {
  const raw = String(value || "").replace(/[^\d+]/g, "");
  if (/^07\d{8}$/.test(raw)) return `254${raw.slice(1)}`;
  if (/^\+2547\d{8}$/.test(raw)) return raw.slice(1);
  if (/^2547\d{8}$/.test(raw)) return raw;
  return null;
}
function safeJson(value, fallback = {}) {
  try { return typeof value === "string" ? JSON.parse(value) : (value || fallback); } catch { return fallback; }
}
function publicService(row) {
  if (!row) return null;
  return {
    id: row.id, name: row.name, slug: row.slug, category: row.category, description: row.description,
    price: Number(row.price), currency: row.currency || "KES", active: row.active !== false,
    featured: Boolean(row.featured), popular: Boolean(row.popular), recommended: Boolean(row.recommended),
    icon: row.icon || "doc", configuration: safeJson(row.configuration, {}), generationType: row.generation_type || row.generationType || "document",
    templates: templatesFor({ id: row.id, generationType: row.generation_type || row.generationType, configuration: safeJson(row.configuration, {}) })
  };
}
function toService(seed) {
  return { id: seed[0], name: seed[1], slug: seed[0], category: seed[2], description: seed[3], price: seed[4], currency: "KES", icon: seed[5], active: seed[6], featured: seed[7], popular: seed[8], recommended: seed[9], generationType: seed[10], configuration: {} };
}
function sendError(res, status, message, code = "request_error") { return res.status(status).json({ error: { code, message } }); }
function publicOrder(order) {
  if (!order) return null;
  return {
    id: order.id, publicOrderId: order.publicOrderId || order.public_order_id, serviceId: order.serviceId || order.service_id,
    serviceName: order.serviceName || order.service_name, amount: Number(order.amount), currency: order.currency || "KES",
    status: order.status, phone: order.phone ? `••••${String(order.phone).slice(-4)}` : undefined,
    createdAt: order.createdAt || order.created_at, updatedAt: order.updatedAt || order.updated_at,
    completedAt: order.completedAt || order.completed_at, result: order.resultMetadata || order.result_metadata || null
  };
}
function statusFromProvider(status, success) {
  const normalized = String(status || "").toLowerCase();
  if (success === true || ["completed", "success", "successful", "paid"].includes(normalized)) return "PAYMENT_SUCCESS";
  if (["failed", "failure"].includes(normalized)) return "PAYMENT_FAILED";
  if (["cancelled", "canceled"].includes(normalized)) return "PAYMENT_CANCELLED";
  if (["expired", "timeout", "timed_out"].includes(normalized)) return "PAYMENT_EXPIRED";
  return null;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  return new Promise((resolve, reject) => crypto.scrypt(String(password), salt, 64, (err, derived) => err ? reject(err) : resolve(`${salt}:${derived.toString("hex")}`)));
}
async function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  return new Promise(resolve => crypto.scrypt(String(password), salt, 64, (err, derived) => resolve(!err && crypto.timingSafeEqual(Buffer.from(hash, "hex"), derived))));
}

async function initDatabase() {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
  if (!pool) {
    memory.services = seedServices.map(toService);
    if (!ADMIN_PASSWORD) console.warn("ADMIN_PASSWORD is not configured; admin login is disabled.");
    else if (!process.env.ADMIN_PASSWORD) console.warn("Using development admin password fallback. Set ADMIN_PASSWORD before production.");
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, phone TEXT UNIQUE, email TEXT, name TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen TIMESTAMPTZ);
    CREATE TABLE IF NOT EXISTS services (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL, price NUMERIC(12,2) NOT NULL CHECK (price >= 0), currency TEXT NOT NULL DEFAULT 'KES', active BOOLEAN NOT NULL DEFAULT TRUE, featured BOOLEAN NOT NULL DEFAULT FALSE, popular BOOLEAN NOT NULL DEFAULT FALSE, recommended BOOLEAN NOT NULL DEFAULT FALSE, icon TEXT, configuration JSONB NOT NULL DEFAULT '{}'::jsonb, generation_type TEXT NOT NULL DEFAULT 'document', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, public_order_id TEXT UNIQUE NOT NULL, user_id TEXT REFERENCES users(id), service_id TEXT REFERENCES services(id), service_name TEXT NOT NULL, amount NUMERIC(12,2) NOT NULL, currency TEXT NOT NULL DEFAULT 'KES', phone TEXT NOT NULL, status TEXT NOT NULL, form_data JSONB NOT NULL DEFAULT '{}'::jsonb, result_metadata JSONB, download_token TEXT UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), completed_at TIMESTAMPTZ);
    CREATE TABLE IF NOT EXISTS payment_attempts (id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id), attempt_number INTEGER NOT NULL, phone TEXT NOT NULL, amount NUMERIC(12,2) NOT NULL, external_reference TEXT UNIQUE NOT NULL, swift_transaction_id TEXT, checkout_request_id TEXT, status TEXT NOT NULL, raw_response JSONB, error_information TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS transactions (transaction_id TEXT PRIMARY KEY, order_id TEXT REFERENCES orders(id), amount NUMERIC(12,2), phone TEXT, reference TEXT, provider TEXT NOT NULL DEFAULT 'swiftwallet', status TEXT NOT NULL, callback_information JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS generated_files (id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id), file_type TEXT NOT NULL, filename TEXT NOT NULL, storage_reference TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ);
    CREATE TABLE IF NOT EXISTS referrals (referral_code TEXT PRIMARY KEY, referrer TEXT, referred_user TEXT, referred_order TEXT, status TEXT NOT NULL DEFAULT 'created', reward_information JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS saved_tools (id TEXT PRIMARY KEY, user_id TEXT, service_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(user_id, service_id));
    CREATE TABLE IF NOT EXISTS admin_users (id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS admin_activity (id TEXT PRIMARY KEY, admin_id TEXT, action TEXT NOT NULL, metadata JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
  `);
  for (const seed of seedServices) {
    const s = toService(seed);
    await pool.query(`INSERT INTO services (id,name,slug,category,description,price,currency,active,featured,popular,recommended,icon,generation_type,configuration) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (id) DO NOTHING`, [s.id, s.name, s.slug, s.category, s.description, s.price, s.currency, s.active, s.featured, s.popular, s.recommended, s.icon, s.generationType, s.configuration]);
  }
  if (ADMIN_PASSWORD) {
    const adminHash = await hashPassword(ADMIN_PASSWORD);
    await pool.query(`INSERT INTO admin_users (id,password_hash) VALUES ('primary',$1) ON CONFLICT (id) DO UPDATE SET password_hash=EXCLUDED.password_hash, updated_at=NOW()`, [adminHash]);
  }
  await pool.query(`INSERT INTO settings (key,value) VALUES ('site',$1) ON CONFLICT (key) DO NOTHING`, [memory.settings]);
}

const store = {
  async services() {
    if (pool) return (await pool.query("SELECT * FROM services WHERE active = TRUE ORDER BY popular DESC, featured DESC, name ASC")).rows.map(publicService);
    return memory.services.filter(s => s.active).map(publicService);
  },
  async service(id) {
    if (pool) return publicService((await pool.query("SELECT * FROM services WHERE id=$1 OR slug=$1 LIMIT 1", [id])).rows[0]);
    return publicService(memory.services.find(s => s.id === id || s.slug === id));
  },
  async allServices() {
    if (pool) return (await pool.query("SELECT * FROM services ORDER BY created_at DESC")).rows.map(publicService);
    return memory.services.map(publicService);
  },
  async saveService(input, existingId = null) {
    const service = { id: existingId || id("svc_"), name: String(input.name || "").trim(), slug: String(input.slug || input.name || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""), category: String(input.category || "Services"), description: String(input.description || ""), price: Math.max(0, Number(input.price || 0)), currency: String(input.currency || "KES").toUpperCase(), active: input.active !== false, featured: Boolean(input.featured), popular: Boolean(input.popular), recommended: Boolean(input.recommended), icon: String(input.icon || "doc"), generationType: String(input.generationType || input.generation_type || "document"), configuration: safeJson(input.configuration, {}) };
    if (!service.name || !service.slug || !Number.isFinite(service.price)) throw new Error("Service name, slug and valid price are required.");
    if (pool) {
      const row = (await pool.query(`INSERT INTO services (id,name,slug,category,description,price,currency,active,featured,popular,recommended,icon,generation_type,configuration) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,slug=EXCLUDED.slug,category=EXCLUDED.category,description=EXCLUDED.description,price=EXCLUDED.price,currency=EXCLUDED.currency,active=EXCLUDED.active,featured=EXCLUDED.featured,popular=EXCLUDED.popular,recommended=EXCLUDED.recommended,icon=EXCLUDED.icon,generation_type=EXCLUDED.generation_type,configuration=EXCLUDED.configuration,updated_at=NOW() RETURNING *`, [service.id, service.name, service.slug, service.category, service.description, service.price, service.currency, service.active, service.featured, service.popular, service.recommended, service.icon, service.generationType, service.configuration])).rows[0];
      return publicService(row);
    }
    const index = memory.services.findIndex(s => s.id === service.id);
    if (index >= 0) memory.services[index] = service; else memory.services.push(service);
    return service;
  },
  async deleteService(idValue) {
    if (pool) return (await pool.query("UPDATE services SET active=FALSE,updated_at=NOW() WHERE id=$1 RETURNING id", [idValue])).rowCount > 0;
    const service = memory.services.find(s => s.id === idValue);
    if (service) service.active = false;
    return Boolean(service);
  },
  async createOrder({ service, phone, formData }) {
    const order = { id: id("ord_"), publicOrderId: `JAZA-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`, serviceId: service.id, serviceName: service.name, amount: service.price, currency: service.currency, phone, status: "CREATED", formData: formData || {}, resultMetadata: null, createdAt: now(), updatedAt: now(), completedAt: null };
    if (pool) {
      await pool.query(`INSERT INTO orders (id,public_order_id,service_id,service_name,amount,currency,phone,status,form_data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [order.id, order.publicOrderId, order.serviceId, order.serviceName, order.amount, order.currency, order.phone, order.status, order.formData]);
    } else memory.orders.push(order);
    return order;
  },
  async order(orderId) {
    if (pool) {
      const row = (await pool.query("SELECT * FROM orders WHERE id=$1 OR public_order_id=$1 LIMIT 1", [orderId])).rows[0];
      return row && { ...row, publicOrderId: row.public_order_id, serviceId: row.service_id, serviceName: row.service_name, formData: row.form_data, resultMetadata: row.result_metadata, createdAt: row.created_at, updatedAt: row.updated_at, completedAt: row.completed_at, downloadToken: row.download_token };
    }
    return memory.orders.find(o => o.id === orderId || o.publicOrderId === orderId);
  },
  async updateOrder(orderId, patch) {
    const current = await this.order(orderId);
    if (!current) return null;
    const next = { ...current, ...patch, updatedAt: now() };
    if (pool) {
      await pool.query(`UPDATE orders SET status=$2,phone=$3,form_data=$4,result_metadata=$5,download_token=$6,updated_at=NOW(),completed_at=$7 WHERE id=$1`, [current.id, next.status, next.phone, next.formData || {}, next.resultMetadata, next.downloadToken || null, next.completedAt || null]);
    } else Object.assign(current, next);
    return next;
  },
  async createAttempt(order, phone, reference, number) {
    const attempt = { id: id("att_"), orderId: order.id, attemptNumber: number, phone, amount: order.amount, externalReference: reference, swiftTransactionId: null, checkoutRequestId: null, status: "created", rawResponse: null, errorInformation: null, createdAt: now(), updatedAt: now() };
    if (pool) await pool.query(`INSERT INTO payment_attempts (id,order_id,attempt_number,phone,amount,external_reference,status) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [attempt.id, attempt.orderId, attempt.attemptNumber, attempt.phone, attempt.amount, attempt.externalReference, attempt.status]);
    else memory.attempts.push(attempt);
    return attempt;
  },
  async attemptsFor(orderId) {
    if (pool) return (await pool.query("SELECT * FROM payment_attempts WHERE order_id=$1 ORDER BY attempt_number DESC", [orderId])).rows.map(a => ({ ...a, orderId: a.order_id, attemptNumber: a.attempt_number, externalReference: a.external_reference, swiftTransactionId: a.swift_transaction_id, checkoutRequestId: a.checkout_request_id, rawResponse: a.raw_response }));
    return memory.attempts.filter(a => a.orderId === orderId).sort((a, b) => b.attemptNumber - a.attemptNumber);
  },
  async updateAttempt(attempt, patch) {
    const next = { ...attempt, ...patch, updatedAt: now() };
    if (pool) await pool.query(`UPDATE payment_attempts SET swift_transaction_id=$2,checkout_request_id=$3,status=$4,raw_response=$5,error_information=$6,updated_at=NOW() WHERE id=$1`, [attempt.id, next.swiftTransactionId || null, next.checkoutRequestId || null, next.status, next.rawResponse || null, next.errorInformation || null]);
    else Object.assign(attempt, next);
    return next;
  },
  async saveTransaction(tx) {
    if (!tx.transactionId) return;
    if (pool) await pool.query(`INSERT INTO transactions (transaction_id,order_id,amount,phone,reference,status,callback_information) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (transaction_id) DO UPDATE SET status=EXCLUDED.status,callback_information=EXCLUDED.callback_information,updated_at=NOW()`, [tx.transactionId, tx.orderId, tx.amount, tx.phone, tx.reference, tx.status, tx.callbackInformation || {}]);
    else {
      const existing = memory.transactions.find(t => t.transactionId === tx.transactionId);
      if (existing) Object.assign(existing, tx, { updatedAt: now() }); else memory.transactions.push({ ...tx, createdAt: now(), updatedAt: now() });
    }
  },
  async saveFile(file) {
    if (pool) await pool.query(`INSERT INTO generated_files (id,order_id,file_type,filename,storage_reference,mime_type,size,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [file.id, file.orderId, file.fileType, file.filename, file.storageReference, file.mimeType, file.size, file.expiresAt]);
    else memory.files.push(file);
  },
  async fileForOrder(orderId) {
    if (pool) return (await pool.query("SELECT * FROM generated_files WHERE order_id=$1 ORDER BY created_at DESC LIMIT 1", [orderId])).rows[0];
    return memory.files.filter(f => f.orderId === orderId).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))[0];
  },
  async orders({ q = "", status = "" } = {}) {
    if (pool) {
      const values = []; const where = [];
      if (status) { values.push(status); where.push(`status=$${values.length}`); }
      if (q) { values.push(`%${q}%`); where.push(`(public_order_id ILIKE $${values.length} OR phone ILIKE $${values.length})`); }
      const rows = (await pool.query(`SELECT * FROM orders ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at DESC LIMIT 200`, values)).rows;
      return rows.map(row => ({ ...row, publicOrderId: row.public_order_id, serviceId: row.service_id, serviceName: row.service_name, createdAt: row.created_at, updatedAt: row.updated_at, completedAt: row.completed_at }));
    }
    return memory.orders.filter(o => (!status || o.status === status) && (!q || `${o.publicOrderId} ${o.phone} ${o.id}`.toLowerCase().includes(q.toLowerCase()))).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).slice(0, 200);
  }
};

async function providerRequest(endpoint, options = {}) {
  if (!API_KEY) return { configured: false };
  const response = await fetch(`${SWIFTWALLET_BASE_URL}${endpoint}`, { ...options, headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "application/json", ...(options.headers || {}) } });
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text.slice(0, 1000) }; }
  return { configured: true, ok: response.ok, status: response.status, data };
}
function providerRecords(data) {
  if (Array.isArray(data)) return data;
  return data?.data || data?.transactions || data?.results || data?.data?.transactions || [];
}
async function verifySwiftTransaction({ transactionId, externalReference, phone }) {
  if (!API_KEY) return { verified: false, configured: false };
  const query = new URLSearchParams({ page: "1", limit: "100" });
  if (phone) query.set("phone_number", phone);
  const result = await providerRequest(`/transactions/?${query.toString()}`);
  if (!result.ok) return { verified: false, configured: true };
  const records = providerRecords(result.data);
  const match = records.find(t => String(t.transaction_id ?? t.id) === String(transactionId) || String(t.external_reference ?? t.reference) === String(externalReference));
  if (!match) return { verified: false, configured: true };
  const status = statusFromProvider(match.status, match.success);
  return { verified: status === "PAYMENT_SUCCESS", status, record: match, configured: true };
}
async function markPaymentSuccess(order, attempt, callback) {
  const current = await store.order(order.id);
  if (!current || current.status === "READY" || current.status === "GENERATING" || current.status === "GENERATION_PENDING") return current;
  await store.updateAttempt(attempt, { status: "completed", rawResponse: callback });
  await store.saveTransaction({ transactionId: String(callback.transaction_id || callback.transactionId), orderId: order.id, amount: callback.result?.Amount || order.amount, phone: callback.result?.Phone || order.phone, reference: attempt.externalReference, status: "completed", callbackInformation: callback });
  const paid = await store.updateOrder(order.id, { status: "GENERATION_PENDING", completedAt: now() });
  setImmediate(() => generateResult(paid).catch(error => console.error("Generation error:", error.message)));
  return paid;
}

function drawHeader(doc, title, subtitle) {
  const options = arguments[3] || {};
  const margin = Number(doc.options.margin || 48);
  const width = doc.page.width;
  const headerColor = options.headerColor || "#173f4a";
  const accent = options.accent || "#c7654f";
  const headingFont = options.headingFont || "Helvetica-Bold";
  const bodyFont = options.bodyFont || "Helvetica";
  doc.fillColor(headerColor).rect(0, 0, width, 92).fill();
  doc.fillColor("#ffffff").font(headingFont).fontSize(25).text(BRAND_NAME, margin, 27);
  doc.font(bodyFont).fontSize(10).fillColor("#d8e7e5").text("Professional work, made local.", margin, 59);
  doc.fillColor(accent).font(headingFont).fontSize(20).text(title, margin, 126);
  doc.fillColor("#617078").font(bodyFont).fontSize(10).text(subtitle || "Prepared with care", margin, 153);
}
function renderCv(doc, data, order) {
  const accentColor = tunedColor(data.themeColor, data.colorIntensity);
  const palette = { accent: accentColor, heading: "#17242b", background: data.background === "tint" ? "#f1f6f5" : data.background === "soft" ? "#f7f5f0" : "#ffffff" };
  const headingFont = data.headingFontPdf || "Helvetica-Bold";
  const bodyFont = data.bodyFontPdf || "Helvetica";
  const margin = Number(doc.options.margin || 48);
  const pageWidth = doc.page.width;
  const contentWidth = pageWidth - margin * 2;
  const sidebar = ["sidebar-left", "sidebar-right"].includes(data.layout) ? Math.min(155, contentWidth * 0.3) : 0;
  const mainX = data.layout === "sidebar-left" ? margin + sidebar + 20 : margin;
  const mainWidth = sidebar ? contentWidth - sidebar - 20 : contentWidth;
  const sidebarX = data.layout === "sidebar-right" ? pageWidth - margin - sidebar : margin;
  const compact = data.density === "compact" || (data.smartFit && String(data.experience || "").length > 850);
  const baseSize = compact ? 9 : data.density === "airy" ? 11 : 10;
  doc._jazaTitle = "CURRICULUM VITAE";
  doc._jazaSubtitle = `${data.template.name} template · ${order.publicOrderId}`;
  drawHeader(doc, "CURRICULUM VITAE", `${data.template.name} template · ${order.publicOrderId}`, { headerColor: accentColor, accent: accentColor, headingFont, bodyFont });
  if (palette.background !== "#ffffff") doc.save().fillColor(palette.background).rect(0, 92, pageWidth, doc.page.height - 92).fill().restore();
  if (data.borderStyle === "box") doc.save().lineWidth(2).strokeColor(palette.accent).rect(margin / 2, margin / 2, pageWidth - margin, doc.page.height - margin).stroke().restore();
  if (data.borderStyle === "accent") doc.save().fillColor(palette.accent).rect(0, 92, 7, doc.page.height - 92).fill().restore();
  doc.fillColor(palette.heading).font(headingFont).fontSize(compact ? 25 : 30).text(data.name, margin, 198);
  doc.fillColor(palette.accent).font(headingFont).fontSize(11).text(data.role || "Professional", margin, 237);
  doc.fillColor("#617078").font(bodyFont).fontSize(9).text([data.email, data.phone, data.location].filter(Boolean).join("  ·  ") || "Contact details", margin, 257, { width: contentWidth });
  if (data.borderStyle !== "none") doc.moveTo(margin, 280).lineTo(margin + contentWidth, 280).stroke("#d5dedb");
  if (sidebar) {
    doc.save().fillColor("#f1f6f5").rect(sidebarX, 305, sidebar, doc.page.height - 350).fill().restore();
    if (data.borderStyle !== "none") doc.moveTo(data.layout === "sidebar-left" ? sidebarX + sidebar : mainX - 10, 305).lineTo(data.layout === "sidebar-left" ? sidebarX + sidebar : mainX - 10, doc.page.height - 45).stroke("#d5dedb");
  }
  let y = 305;
  const section = (title, body, height = 40) => {
    ensurePdfSpace(doc, height + 30);
    if (doc._jazaPageBreak) {
      y = doc.y;
      doc._jazaPageBreak = false;
    } else {
      y = doc.y = Math.max(y, doc.y);
    }
    doc.fillColor(palette.accent).font(headingFont).fontSize(10).text(title.toUpperCase(), mainX, y);
    if (data.borderStyle !== "none") doc.moveTo(mainX, y + 17).lineTo(mainX + mainWidth, y + 17).stroke("#d5dedb");
    doc.y = y + 29;
    body();
    y = doc.y + 20;
  };
  if (data.summary) section("Profile", () => doc.fillColor(palette.heading).font(bodyFont).fontSize(baseSize).text(data.summary, mainX, doc.y, { width: mainWidth, lineGap: data.density === "airy" ? 5 : 3 }));
  if (data.hasExperience) section("Experience", () => data.experience.forEach(item => {
    const description = [item.description, item.company, item.dates].filter(Boolean).join("  ·  ");
    const height = doc.heightOfString(description || " ", { width: mainWidth, font: bodyFont, fontSize: compact ? 8 : 9, lineGap: 3 }) + 30;
    ensurePdfSpace(doc, height);
    doc.fillColor(palette.heading).font(headingFont).fontSize(compact ? 10 : 11).text(item.role || "Role", mainX, doc.y);
    doc.fillColor("#617078").font(bodyFont).fontSize(compact ? 8 : 9).text(description || "Experience detail", mainX, doc.y + 15, { width: mainWidth, lineGap: 3 });
    doc.y += height - 4;
  }));
  if (data.hasEducation) section("Education", () => data.education.forEach(item => {
    ensurePdfSpace(doc, 32);
    doc.fillColor(palette.heading).font(headingFont).fontSize(10).text(item.qualification || "Education", mainX, doc.y);
    doc.fillColor("#617078").font(bodyFont).fontSize(9).text([item.school, item.dates].filter(Boolean).join("  ·  "), mainX, doc.y + 14, { width: mainWidth });
    doc.y += 32;
  }));
  if (data.hasSkills && !sidebar) section("Skills", () => {
    doc.fillColor(palette.heading).font(bodyFont).fontSize(baseSize).text(data.skills.join("  ·  "), mainX, doc.y, { width: mainWidth, lineGap: 4 });
  });
  if (sidebar && data.hasSkills) {
    const sidebarY = 320;
    doc.fillColor(palette.accent).font(headingFont).fontSize(10).text("SKILLS", sidebarX + 14, sidebarY);
    doc.fillColor(palette.heading).font(bodyFont).fontSize(9).text(data.skills.join("  ·  "), sidebarX + 14, sidebarY + 24, { width: sidebar - 28, lineGap: 4 });
  }
  if (!data.hasExperience && !data.hasEducation && !data.hasSkills) section("Professional focus", () => doc.fillColor("#617078").font(bodyFont).fontSize(baseSize).text("Add experience, education or skills to expand this CV.", mainX, doc.y, { width: mainWidth }));
  drawPageFooter(doc);
}

function renderBusinessDocument(doc, data, service, order) {
  const title = data.type === "invoice" ? "INVOICE" : data.type === "receipt" ? "RECEIPT" : data.type === "quotation" ? "QUOTATION" : service.name.toUpperCase();
  doc._jazaTitle = title;
  doc._jazaSubtitle = `${data.template.name} template · ${order.publicOrderId}`;
  drawHeader(doc, title, `${data.template.name} template · ${order.publicOrderId}`);
  doc.fillColor("#17242b").font("Helvetica-Bold").fontSize(16).text(data.name, 48, 198);
  doc.font("Helvetica").fontSize(10).fillColor("#617078").text(data.customer || data.location || "Prepared for your business", 48, 220);
  doc.fillColor("#17242b").font("Helvetica-Bold").fontSize(10).text("DOCUMENT DETAILS", 380, 198);
  doc.font("Helvetica").fillColor("#617078").text(`Reference  ${order.publicOrderId}`, 380, 218).text(`Date  ${data.date}`, 380, 234);
  doc.moveTo(48, 272).lineTo(564, 272).stroke("#d5dedb");
  doc.fillColor("#16786f").font("Helvetica-Bold").fontSize(10).text("DESCRIPTION", 48, 294).text("QTY", 370, 294).text("AMOUNT", 450, 294);
  doc.y = 324;
  data.items.forEach(item => {
    const amount = item.quantity * item.unitPrice;
    const height = doc.heightOfString(item.description, { width: 295, font: "Helvetica", fontSize: 10, lineGap: 3 }) + 18;
    ensurePdfSpace(doc, height + 35, 120);
    doc.fillColor("#17242b").font("Helvetica").fontSize(10).text(item.description, 48, doc.y, { width: 295, lineGap: 3 });
    doc.text(String(item.quantity), 370, doc.y);
    doc.text(money(amount, service.currency), 450, doc.y);
    doc.moveTo(48, doc.y + height - 5).lineTo(564, doc.y + height - 5).stroke("#eef1ef");
    doc.y += height + 8;
  });
  ensurePdfSpace(doc, 100);
  doc.moveTo(320, doc.y).lineTo(564, doc.y).stroke("#d5dedb");
  doc.y += 14;
  doc.fillColor("#617078").font("Helvetica").fontSize(10).text("Subtotal", 370, doc.y).text(money(data.subtotal, service.currency), 450, doc.y);
  if (data.taxRate > 0) {
    doc.y += 17;
    doc.text(`Tax (${data.taxRate}%)`, 370, doc.y).text(money(data.subtotal * data.taxRate / 100, service.currency), 450, doc.y);
  }
  doc.y += 23;
  doc.fillColor("#173f4a").font("Helvetica-Bold").fontSize(13).text(data.type === "receipt" ? "PAID TOTAL" : "TOTAL", 320, doc.y).text(money(data.total, service.currency), 450, doc.y);
  doc.y += 55;
  doc.fillColor("#617078").font("Helvetica").fontSize(9).text(data.summary || "Thank you for choosing a local creative partner.", 48, doc.y, { width: 516, lineGap: 4 });
  drawPageFooter(doc);
}

function createProfessionalPdf(order, service) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const data = structuredData(order, service);
    const dimensions = pageDimensions(data);
    const margin = data.density === "compact" ? 38 : data.density === "airy" ? 58 : 48;
    const doc = new PDFDocument({ size: dimensions, margin, bufferPages: true });
    doc.on("data", chunk => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
    if (data.type === "cv") renderCv(doc, data, order);
    else if (["invoice", "receipt", "quotation"].includes(data.type)) renderBusinessDocument(doc, data, service, order);
    else if (data.type === "certificate") {
      doc.rect(30, 30, 535, 780).lineWidth(2).stroke("#c7654f");
      doc.font("Helvetica-Bold").fontSize(18).fillColor("#16786f").text(BRAND_NAME.toUpperCase(), 0, 90, { align: "center" });
      doc.font("Times-Bold").fontSize(38).fillColor("#173f4a").text(data.headline || "CERTIFICATE OF ACHIEVEMENT", 70, 170, { align: "center", width: 470 });
      doc.font("Helvetica").fontSize(13).fillColor("#617078").text("This certificate is proudly presented to", 70, 270, { align: "center", width: 470 });
      doc.font("Times-Bold").fontSize(31).fillColor("#c7654f").text(data.name, 70, 310, { align: "center", width: 470 });
      doc.moveTo(160, 360).lineTo(450, 360).stroke("#d5dedb");
      doc.font("Helvetica").fontSize(12).fillColor("#17242b").text(data.business || BRAND_NAME, 0, 420, { align: "center" });
      doc.fontSize(10).fillColor("#617078").text(data.date, 0, 590, { align: "center" });
      drawPageFooter(doc);
    } else if (data.type === "stamp") {
      drawHeader(doc, "Business Stamp", "A reusable business graphic — not an official government seal");
      const square = data.template.id === "square" || data.shape === "Square";
      if (square) doc.rect(175, 250, 262, 220).lineWidth(4).stroke("#16786f");
      else { doc.circle(306, 360, 120).lineWidth(4).stroke("#16786f"); doc.circle(306, 360, 98).lineWidth(1).stroke("#c7654f"); }
      doc.fillColor("#173f4a").font("Helvetica-Bold").fontSize(18).text(data.name.toUpperCase(), 165, 325, { width: 282, align: "center" });
      doc.font("Helvetica").fontSize(11).text(data.reg || "REGISTRATION NO.", 165, 355, { width: 282, align: "center" }).fontSize(10).text(data.location || "KENYA", 165, 388, { width: 282, align: "center" });
      drawPageFooter(doc);
    } else {
      doc._jazaTitle = service.name.toUpperCase();
      doc._jazaSubtitle = `${data.template.name} template · ${order.publicOrderId}`;
      drawHeader(doc, service.name.toUpperCase(), `${data.template.name} template · ${order.publicOrderId}`);
      doc.fillColor("#17242b").font("Helvetica-Bold").fontSize(16).text(data.name, 48, 198);
      doc.font("Helvetica").fontSize(11).fillColor("#617078").text(data.headline || data.description || service.description, 48, 232, { width: 516, lineGap: 4 });
      doc.y = 320;
      if (data.items.length) data.items.forEach(item => doc.font("Helvetica").fontSize(11).fillColor("#17242b").text(item.description, 48, doc.y, { width: 516 }));
      drawPageFooter(doc);
    }
    doc.end();
  });
}
async function generateResult(order) {
  const service = await store.service(order.serviceId); if (!service) throw new Error("Service no longer exists.");
  await store.updateOrder(order.id, { status: "GENERATING" });
  const buffer = await createProfessionalPdf(order, service);
  const token = crypto.randomBytes(32).toString("hex"); const filename = `${order.publicOrderId.toLowerCase()}.pdf`; const storageReference = path.join(STORAGE_DIR, `${token}.pdf`);
  fs.writeFileSync(storageReference, buffer);
  const expiresAt = new Date(Date.now() + Number(memory.settings.downloadExpiryDays || 30) * 86400000).toISOString();
  await store.saveFile({ id: id("file_"), orderId: order.id, fileType: "pdf", filename, storageReference, mimeType: "application/pdf", size: buffer.length, createdAt: now(), expiresAt });
  await store.updateOrder(order.id, { status: "READY", downloadToken: token, resultMetadata: { filename, mimeType: "application/pdf", size: buffer.length, expiresAt }, completedAt: now() });
}

function adminAuth(req, res, next) {
  const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "") || req.headers["x-admin-token"] || req.cookies?.admin_session;
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) return sendError(res, 401, "Admin authentication required.", "admin_auth_required");
  req.admin = session; next();
}
function parseCookies(req, _res, next) {
  req.cookies = Object.fromEntries(String(req.headers.cookie || "").split(";").filter(Boolean).map(pair => { const [key, ...rest] = pair.trim().split("="); return [key, decodeURIComponent(rest.join("="))]; }));
  next();
}
function recordActivity(action, metadata = {}) {
  const item = { id: id("act_"), action, metadata, createdAt: now() };
  if (pool) pool.query("INSERT INTO admin_activity (id,action,metadata) VALUES ($1,$2,$3)", [item.id, action, metadata]).catch(error => console.error("Activity log error:", error.message));
  else memory.activity.unshift(item);
}

const TEMPLATE_CATALOG = {
  cv: [
    { id: "elegant", name: "Elegant", description: "Expressive and spacious for people who want a memorable first impression." },
    { id: "corporate", name: "Corporate", description: "Clear and confident for established teams and business roles." },
    { id: "luxury", name: "Luxury", description: "Polished with presence, using considered typography and generous space." },
    { id: "simple", name: "Simple", description: "Quiet and direct, keeping attention on your experience." },
    { id: "ats-friendly", name: "ATS-friendly", description: "Straightforward structure that is easy for applicant systems to scan." }
  ],
  invoice: [
    { id: "clean", name: "Clean Ledger", description: "Clear totals and line items with a calm business finish." },
    { id: "modern", name: "Modern Studio", description: "A bold branded invoice for independent businesses." }
  ],
  quotation: [{ id: "modern", name: "Modern Quote", description: "A confident quote designed to make the next step easy." }],
  receipt: [{ id: "clean", name: "Clean Receipt", description: "A concise proof of payment for customers." }],
  certificate: [{ id: "formal", name: "Formal Recognition", description: "A considered certificate with room for the achievement." }],
  stamp: [
    { id: "round", name: "Round", description: "A classic round business graphic." },
    { id: "square", name: "Square", description: "A compact square business graphic." }
  ]
};

function rendererType(service) {
  return String(service?.generationType || service?.id || "").split("-")[0].toLowerCase();
}
function templatesFor(service) {
  const configured = service?.configuration?.templates;
  if (Array.isArray(configured) && configured.length) return configured;
  return TEMPLATE_CATALOG[rendererType(service)] || [{ id: "standard", name: "Standard", description: "A professional JazaTools layout." }];
}
function selectedTemplate(service, values) {
  const templates = templatesFor(service);
  const requested = String(values?.template || "").toLowerCase();
  return templates.find(template => template.id === requested) || templates[0];
}
function asNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}
function safeColor(value, fallback) {
  const color = String(value || "").trim();
  return /^#[0-9a-f]{6}$/i.test(color) ? color : fallback;
}
function tunedColor(value, intensity) {
  const color = safeColor(value, "#173f4a");
  if (intensity === "balanced") return color;
  const rgb = color.slice(1).match(/.{2}/g).map(pair => parseInt(pair, 16));
  const target = intensity === "subtle" ? [255, 255, 255] : [0, 0, 0];
  const amount = intensity === "subtle" ? 0.28 : 0.14;
  return `#${rgb.map((channel, index) => Math.round(channel + (target[index] - channel) * amount).toString(16).padStart(2, "0")).join("")}`;
}
function pdfFont(value, fallback = "Helvetica") {
  const serif = ["Merriweather", "Playfair Display", "Georgia", "Times New Roman"].includes(String(value));
  return serif ? "Times" : fallback;
}
function pageDimensions(data) {
  const sizes = { A4: [595.28, 841.89], LETTER: [612, 792], A5: [419.53, 595.28] };
  let dimensions = sizes[String(data.pageSize || "A4").toUpperCase()] || [asNumber(data.customWidth, 210) * 2.83465, asNumber(data.customHeight, 297) * 2.83465];
  if (!Number.isFinite(dimensions[0]) || dimensions[0] < 170 || !Number.isFinite(dimensions[1]) || dimensions[1] < 170) dimensions = sizes.A4;
  const landscape = String(data.orientation || "portrait").toLowerCase() === "landscape";
  const isLandscape = dimensions[0] > dimensions[1];
  if (landscape !== isLandscape) dimensions = [dimensions[1], dimensions[0]];
  return dimensions;
}
function asList(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (typeof value === "string") {
    const parsed = safeJson(value, null);
    if (Array.isArray(parsed)) return parsed.filter(Boolean);
    return value.split(/\n+/).map(item => item.trim()).filter(Boolean);
  }
  return [];
}
function structuredData(order, service) {
  const source = order.formData || {};
  const experience = asList(source.experience).map(item => typeof item === "string"
    ? { role: item, company: "", dates: "", description: "" }
    : { role: item.role || item.title || "", company: item.company || item.business || "", dates: item.dates || item.date || "", description: item.description || item.summary || "" })
    .filter(item => item.role || item.company || item.description);
  const education = asList(source.education).map(item => typeof item === "string"
    ? { school: item, qualification: "", dates: "" }
    : { school: item.school || item.institution || "", qualification: item.qualification || item.degree || "", dates: item.dates || item.date || "" })
    .filter(item => item.school || item.qualification);
  const skills = asList(source.skills).flatMap(item => String(item).split(",")).map(item => item.trim()).filter(Boolean);
  const items = asList(source.items).map(item => typeof item === "string"
    ? { description: item.split("|")[0].trim(), quantity: asNumber(item.split("|")[1], 1), unitPrice: asNumber(item.split("|")[2], 0) }
    : { description: item.description || item.item || "", quantity: asNumber(item.quantity || item.qty, 1), unitPrice: asNumber(item.unitPrice || item.price, 0) })
    .filter(item => item.description);
  if (!items.length && (source.item || source.description || source.headline)) {
    items.push({ description: source.item || source.headline || source.description, quantity: asNumber(source.qty, 1), unitPrice: asNumber(source.price, order.amount) });
  }
  const subtotal = items.reduce((sum, item) => sum + item.quantity * item.unitPrice, 0);
  const taxRate = asNumber(source.tax, 0);
  const total = subtotal + subtotal * taxRate / 100;
  return {
    ...source,
    type: rendererType(service),
    template: selectedTemplate(service, source),
    layout: String(source.layout || "single"),
    pageSize: String(source.pageSize || "A4").toUpperCase() === "US LETTER" ? "LETTER" : String(source.pageSize || "A4"),
    orientation: String(source.orientation || "portrait").toLowerCase() === "landscape" ? "landscape" : "portrait",
    themeColor: safeColor(source.themeColor, "#173f4a"),
    colorIntensity: String(source.colorIntensity || "balanced"),
    headingFont: source.headingFont || "Inter",
    bodyFont: source.bodyFont || "Inter",
    headingFontPdf: pdfFont(source.headingFont),
    bodyFontPdf: pdfFont(source.bodyFont),
    background: ["paper", "soft", "tint"].includes(source.background) ? source.background : "paper",
    borderStyle: ["line", "accent", "box", "none"].includes(source.borderStyle) ? source.borderStyle : "line",
    iconStyle: source.iconStyle === "none" ? "none" : "minimal",
    density: ["airy", "balanced", "compact"].includes(source.density) ? source.density : "balanced",
    smartFit: source.smartFit !== false && source.smartFit !== "false",
    experience,
    education,
    skills,
    items,
    subtotal: subtotal || asNumber(source.price, order.amount),
    taxRate,
    total: total || asNumber(source.price, order.amount),
    hasExperience: experience.length > 0,
    hasEducation: education.length > 0,
    hasSkills: skills.length > 0,
    hasItems: items.length > 0,
    name: source.name || source.business || source.customer || "Client",
    date: source.date || new Date().toLocaleDateString("en-KE")
  };
}
function money(value, currency = "KES") {
  return `${currency === "KES" ? "KSh" : currency} ${asNumber(value).toLocaleString("en-KE", { maximumFractionDigits: 2 })}`;
}
function ensurePdfSpace(doc, required, top = 115) {
  const bottom = doc.page.height - 42;
  if (doc.y + required <= bottom) return;
  doc.addPage();
  drawHeader(doc, doc._jazaTitle, doc._jazaSubtitle);
  doc.y = Math.min(top, doc.page.height - 120);
  doc._jazaPageBreak = true;
}
function drawPageFooter(doc) {
  const range = doc.bufferedPageRange ? doc.bufferedPageRange() : { start: 0, count: 1 };
  const footerY = doc.page.height - 30;
  for (let index = range.start; index < range.start + range.count; index += 1) {
    doc.switchToPage(index);
    const margin = Number(doc.options.margin || 48);
    doc.save().fillColor("#617078").font("Helvetica").fontSize(8).text(`${BRAND_NAME} · Professional work, made local.`, margin, footerY);
    doc.text(`Page ${index + 1}`, doc.page.width - margin - 64, footerY, { width: 64, align: "right" }).restore();
  }
}

app.use(helmet({ crossOriginResourcePolicy: false, contentSecurityPolicy: false }));
app.use(cors({ origin: (process.env.FRONTEND_ORIGINS || "*").split(",").includes("*") ? true : (process.env.FRONTEND_ORIGINS || "").split(","), credentials: true }));
app.use(express.json({ limit: "1mb" }));
app.use(parseCookies);
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: "draft-7", legacyHeaders: false }));

app.get("/api/health", async (_req, res) => res.json({ ok: true, service: BRAND_NAME, database: Boolean(pool), paymentsConfigured: Boolean(API_KEY), timestamp: now() }));
app.get("/api/services", async (_req, res) => { try { res.json({ services: await store.services(), brandName: BRAND_NAME }); } catch { sendError(res, 500, "Services are temporarily unavailable."); } });
app.get("/api/services/:id", async (req, res) => { try { const service = await store.service(req.params.id); return service ? res.json({ service }) : sendError(res, 404, "Service not found.", "service_not_found"); } catch { sendError(res, 500, "Service is temporarily unavailable."); } });

app.post("/api/orders", async (req, res) => {
  try {
    const service = await store.service(req.body.serviceId || req.body.service_id); const phone = normalizePhone(req.body.phone);
    if (!service || !service.active) return sendError(res, 400, "Choose an active service.", "invalid_service");
    if (!phone) return sendError(res, 400, "Enter a valid Kenyan M-Pesa number.", "invalid_phone");
    const order = await store.createOrder({ service, phone, formData: safeJson(req.body.formData, {}) });
    res.status(201).json({ order: publicOrder(order), amount: service.price });
  } catch (error) { sendError(res, 400, error.message || "Unable to create order."); }
});
app.get("/api/orders/:id", async (req, res) => { try { const order = await store.order(req.params.id); return order ? res.json({ order: publicOrder(order) }) : sendError(res, 404, "Order not found.", "order_not_found"); } catch { sendError(res, 500, "Order is temporarily unavailable."); } });
app.get("/api/orders/by-phone", async (req, res) => {
  const phone = normalizePhone(req.query.phone); if (!phone) return sendError(res, 400, "Enter a valid Kenyan phone number.", "invalid_phone");
  const orders = (await store.orders()).filter(o => o.phone === phone).map(publicOrder); res.json({ orders });
});

async function initiatePayment(req, res) {
  try {
    const order = await store.order(req.body.orderId || req.body.order_id); if (!order) return sendError(res, 404, "Order not found.", "order_not_found");
    if (["PAYMENT_SUCCESS", "GENERATION_PENDING", "GENERATING", "READY"].includes(order.status)) return res.json({ order: publicOrder(order), message: "This order has already been paid." });
    const phone = normalizePhone(req.body.phone) || order.phone; if (!phone) return sendError(res, 400, "Enter a valid Kenyan M-Pesa number.", "invalid_phone");
    const previous = await store.attemptsFor(order.id); const attempt = await store.createAttempt(order, phone, `JAZA-${order.publicOrderId}-${previous.length + 1}`, previous.length + 1);
    await store.updateOrder(order.id, { phone, status: "PAYMENT_PENDING" });
    const provider = await providerRequest("/stk-initiate/", { method: "POST", body: JSON.stringify({ amount: Math.round(Number(order.amount)), phone_number: phone, external_reference: attempt.externalReference, customer_name: order.formData?.name || order.formData?.business || BRAND_NAME, callback_url: CALLBACK_URL }) });
    if (!provider.configured) return sendError(res, 503, "Payment service temporarily unavailable. Please try again shortly.", "payment_not_configured");
    if (!provider.ok || provider.data?.success === false) {
      await store.updateAttempt(attempt, { status: "failed", rawResponse: provider.data, errorInformation: provider.data?.message || `SwiftWallet HTTP ${provider.status}` });
      await store.updateOrder(order.id, { status: "PAYMENT_FAILED" });
      return sendError(res, 502, "Payment could not be started. Your information is still saved.", "payment_provider_rejected");
    }
    const data = provider.data || {};
    await store.updateAttempt(attempt, { status: "sent", rawResponse: data, swiftTransactionId: data.transaction_id ? String(data.transaction_id) : null, checkoutRequestId: data.checkout_request_id || null });
    const updated = await store.updateOrder(order.id, { status: "AWAITING_CONFIRMATION" });
    res.json({ order: publicOrder(updated), payment: { attemptId: attempt.id, externalReference: attempt.externalReference, checkoutRequestId: data.checkout_request_id || null, message: data.message || "STK Push sent. Please check your phone." } });
  } catch (error) { console.error("Payment initiation error:", error.message); sendError(res, 502, "Payment service temporarily unavailable. Please try again shortly.", "payment_service_unavailable"); }
}
app.post("/api/payments/initiate", initiatePayment);
app.post("/api/payments/retry", initiatePayment);
app.get("/api/payments/status/:orderId", async (req, res) => {
  try {
    const order = await store.order(req.params.orderId); if (!order) return sendError(res, 404, "Order not found.", "order_not_found");
    const attempts = await store.attemptsFor(order.id); const attempt = attempts[0];
    if (attempt && attempt.swiftTransactionId && ["AWAITING_CONFIRMATION", "PAYMENT_PENDING", "STK_SENT"].includes(order.status)) {
      const verification = await verifySwiftTransaction({ transactionId: attempt.swiftTransactionId, externalReference: attempt.externalReference, phone: order.phone });
      if (verification.verified) await markPaymentSuccess(order, attempt, verification.record);
    }
    const latest = await store.order(order.id); res.json({ order: publicOrder(latest), providerConfigured: Boolean(API_KEY) });
  } catch { sendError(res, 502, "Unable to verify payment right now."); }
});
app.post("/api/payments/webhook", async (req, res) => {
  try {
    const callback = req.body || {}; const reference = callback.external_reference || callback.externalReference;
    const attempts = pool ? (await pool.query("SELECT * FROM payment_attempts WHERE external_reference=$1 LIMIT 1", [reference])).rows : memory.attempts.filter(a => a.externalReference === reference);
    const rawAttempt = attempts[0]; if (!rawAttempt) return res.status(202).json({ received: true });
    const attempt = pool ? { ...rawAttempt, id: rawAttempt.id, orderId: rawAttempt.order_id, attemptNumber: rawAttempt.attempt_number, externalReference: rawAttempt.external_reference, swiftTransactionId: rawAttempt.swift_transaction_id } : rawAttempt;
    const order = await store.order(attempt.orderId); if (!order) return res.status(202).json({ received: true });
    const providerStatus = statusFromProvider(callback.status, callback.success);
    if (providerStatus === "PAYMENT_SUCCESS") {
      const verified = await verifySwiftTransaction({ transactionId: callback.transaction_id, externalReference: reference, phone: order.phone });
      if (!verified.verified) return sendError(res, 409, "Payment callback is awaiting provider verification.", "verification_pending");
      await markPaymentSuccess(order, attempt, { ...callback, ...verified.record });
    } else if (providerStatus) {
      await store.updateAttempt(attempt, { status: providerStatus.toLowerCase(), rawResponse: callback });
      await store.updateOrder(order.id, { status: providerStatus });
    }
    res.json({ received: true });
  } catch { sendError(res, 500, "Callback could not be processed."); }
});
app.post("/api/generate/:orderId", async (req, res) => {
  const order = await store.order(req.params.orderId); if (!order) return sendError(res, 404, "Order not found.");
  if (order.status !== "PAYMENT_SUCCESS" && !["GENERATION_PENDING", "GENERATING", "READY"].includes(order.status)) return sendError(res, 403, "Generation unlocks only after verified payment.", "payment_required");
  try { if (order.status === "PAYMENT_SUCCESS") await generateResult(order); const updated = await store.order(order.id); res.json({ order: publicOrder(updated) }); } catch { sendError(res, 500, "Your payment is confirmed, but generation needs another attempt."); }
});
app.get("/api/download/:orderId", async (req, res) => {
  const order = await store.order(req.params.orderId); if (!order || order.status !== "READY") return sendError(res, 404, "This file is not ready.", "file_not_ready");
  if (!req.query.token || req.query.token !== order.downloadToken) return sendError(res, 403, "This download link is not authorized.", "download_forbidden");
  const file = await store.fileForOrder(order.id); if (!file || !fs.existsSync(file.storage_reference || file.storageReference)) return sendError(res, 404, "File is no longer available.", "file_missing");
  const filePath = file.storage_reference || file.storageReference; if (file.expires_at && new Date(file.expires_at) < new Date()) return sendError(res, 410, "This download has expired.", "download_expired");
  res.download(filePath, file.filename, { headers: { "Content-Type": file.mime_type || file.mimeType || "application/pdf", "Cache-Control": "private, no-store" } });
});

app.post("/api/admin/login", async (req, res) => {
  if (!ADMIN_PASSWORD) return sendError(res, 503, "Admin password is not configured.", "admin_not_configured");
  const password = String(req.body.password || ""); let valid = false;
  if (pool) { const row = (await pool.query("SELECT password_hash FROM admin_users WHERE id='primary'")).rows[0]; valid = await verifyPassword(password, row?.password_hash); }
  else { if (!memory.adminHash) memory.adminHash = await hashPassword(ADMIN_PASSWORD); valid = await verifyPassword(password, memory.adminHash); }
  if (!valid) return sendError(res, 401, "Incorrect password.", "invalid_credentials");
  const token = crypto.randomBytes(32).toString("hex"); sessions.set(token, { id: "primary", expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
  res.cookie?.("admin_session", token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000 });
  recordActivity("login"); res.json({ token, expiresIn: 28800 });
});
app.get("/api/admin/dashboard", adminAuth, async (_req, res) => {
  const orders = await store.orders(); const successful = orders.filter(o => ["PAYMENT_SUCCESS", "GENERATION_PENDING", "GENERATING", "READY"].includes(o.status)); const today = new Date().toISOString().slice(0, 10);
  const popular = {}; orders.forEach(o => { popular[o.serviceName] = (popular[o.serviceName] || 0) + 1; });
  res.json({ totals: { orders: orders.length, successfulPayments: successful.length, pendingPayments: orders.filter(o => ["PAYMENT_PENDING", "AWAITING_CONFIRMATION"].includes(o.status)).length, failedPayments: orders.filter(o => ["PAYMENT_FAILED", "PAYMENT_CANCELLED", "PAYMENT_EXPIRED"].includes(o.status)).length, revenue: successful.reduce((sum, o) => sum + Number(o.amount), 0), todaysOrders: orders.filter(o => String(o.createdAt || "").slice(0, 10) === today).length, todaysRevenue: successful.filter(o => String(o.createdAt || "").slice(0, 10) === today).reduce((sum, o) => sum + Number(o.amount), 0) }, popularServices: Object.entries(popular).sort((a, b) => b[1] - a[1]).slice(0, 5), recentTransactions: orders.slice(0, 8).map(publicOrder) });
});
app.get("/api/admin/orders", adminAuth, async (req, res) => res.json({ orders: (await store.orders({ q: String(req.query.q || ""), status: String(req.query.status || "") })).map(publicOrder) }));
app.get("/api/admin/transactions", adminAuth, async (_req, res) => {
  if (pool) return res.json({ transactions: (await pool.query("SELECT * FROM transactions ORDER BY created_at DESC LIMIT 300")).rows });
  res.json({ transactions: memory.transactions.slice(0, 300) });
});
app.get("/api/admin/services", adminAuth, async (_req, res) => res.json({ services: await store.allServices() }));
app.post("/api/admin/services", adminAuth, async (req, res) => { try { const service = await store.saveService(req.body); recordActivity("service_creation", { id: service.id }); res.status(201).json({ service }); } catch (error) { sendError(res, 400, error.message); } });
app.put("/api/admin/services/:id", adminAuth, async (req, res) => { try { const service = await store.saveService(req.body, req.params.id); recordActivity("service_update", { id: service.id }); res.json({ service }); } catch (error) { sendError(res, 400, error.message); } });
app.delete("/api/admin/services/:id", adminAuth, async (req, res) => { const ok = await store.deleteService(req.params.id); if (!ok) return sendError(res, 404, "Service not found."); recordActivity("service_disable", { id: req.params.id }); res.json({ ok: true }); });
app.get("/api/admin/settings", adminAuth, async (_req, res) => { if (pool) { const rows = (await pool.query("SELECT key,value FROM settings")).rows; return res.json({ settings: Object.fromEntries(rows.map(r => [r.key, r.value])) }); } res.json({ settings: memory.settings }); });
app.put("/api/admin/settings", adminAuth, async (req, res) => { const settings = { ...memory.settings, ...req.body }; memory.settings = settings; if (pool) await pool.query(`INSERT INTO settings (key,value) VALUES ('site',$1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`, [settings]); recordActivity("setting_changes", { keys: Object.keys(req.body || {}) }); res.json({ settings }); });
app.post("/api/admin/test-stk", adminAuth, async (req, res) => {
  const phone = normalizePhone(req.body.phone); const amount = Math.round(Number(req.body.amount)); if (!phone || !Number.isFinite(amount) || amount < 1) return sendError(res, 400, "Enter a valid phone number and amount.");
  const result = await providerRequest("/stk-initiate/", { method: "POST", body: JSON.stringify({ amount, phone_number: phone, external_reference: `TEST-${id()}`, customer_name: "JazaTools test payment", callback_url: CALLBACK_URL }) });
  if (!result.configured) return sendError(res, 503, "Payment service temporarily unavailable because SwiftWallet is not configured.");
  if (!result.ok || result.data?.success === false) return sendError(res, 502, result.data?.message || "SwiftWallet rejected the test payment.");
  res.json({ ok: true, provider: result.data });
});

app.use(express.static(__dirname, { index: false, dotfiles: "deny" }));
app.get("/admin", (_req, res) => res.sendFile(path.join(__dirname, "admin.html")));
app.use((_req, res) => res.sendFile(path.join(__dirname, "index.html")));

initDatabase().then(() => app.listen(PORT, () => console.log(`${BRAND_NAME} listening on port ${PORT}`))).catch(error => { console.error("Startup failed:", error); process.exit(1); });