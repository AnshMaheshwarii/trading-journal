import React, { useEffect, useMemo, useRef, useState } from "react";

/**
 * Security model
 * - Per-user encrypted state sealed with PIN (PBKDF2 + AES-GCM)
 * - NEW: Tamper-evident trade log via hash chain (SHA-256)
 * - NEW: Auto-lock after 2 minutes of inactivity
 */

const ACCOUNTS_KEY = "TDASH_ACCOUNTS_V1";

// ---------- base64 helpers ----------
const toB64 = (buf) => btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(buf))));
const fromB64 = (b64) => Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); }).buffer;

// ---------- crypto: PIN sealing ----------
async function deriveKey(pin, saltB64) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
  const salt = saltB64 ? fromB64(saltB64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  return { key, saltB64: saltB64 || toB64(salt) };
}
async function encryptJson(obj, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { ivB64: toB64(iv), ctB64: toB64(ct) };
}
async function decryptJson(payload, key) {
  const iv = new Uint8Array(fromB64(payload.ivB64));
  const ct = fromB64(payload.ctB64);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  const dec = new TextDecoder();
  return JSON.parse(dec.decode(ptBuf));
}

// ---------- hash chain (tamper-evident) ----------
function bytesToHex(buf) {
  const b = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const h = b[i].toString(16).padStart(2, "0");
    s += h;
  }
  return s;
}
async function sha256Hex(text) {
  const enc = new TextEncoder();
  const h = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return bytesToHex(h);
}
/**
 * Compute hash for a trade given previous hash and core fields.
 * We avoid backticks to keep things copy-paste safe.
 */
async function computeTradeHash(prevHash, trade) {
  const base =
    "prev:" + (prevHash || "") +
    "|date:" + (trade.date || "") +
    "|pnl:" + String(trade.profitLoss) +
    "|note:" + (trade.note || "");
  return sha256Hex(base);
}
/**
 * Rebuild chain (from oldest->newest) and return {tradesWithHashes, ok, breakAt}
 */
async function rebuildChain(tradesNewestFirst) {
  const chrono = [...tradesNewestFirst].reverse(); // oldest -> newest
  let prev = "";
  const withHashes = [];
  let ok = true;
  let breakAt = -1;

  for (let i = 0; i < chrono.length; i++) {
    const t = chrono[i];
    const core = { date: t.date, profitLoss: t.profitLoss, note: t.note || "" };
    const expectedHash = await computeTradeHash(prev, core);

    // if incoming already had hashes, we can compare; otherwise we assign
    if (t.hash && t.prevHash) {
      if (t.prevHash !== prev || t.hash !== expectedHash) {
        ok = false;
        breakAt = i; // index in chronological order where it broke
      }
    }

    const newT = {
      ...t,
      prevHash: prev,
      hash: expectedHash
    };
    withHashes.push(newT);
    prev = expectedHash;
  }

  // return newest-first array
  return { tradesWithHashes: withHashes.reverse(), ok, breakAt };
}

function loadAccounts() {
  try {
    const raw = localStorage.getItem(ACCOUNTS_KEY);
    return raw ? JSON.parse(raw) : { lastUser: "", users: {} };
  } catch {
    return { lastUser: "", users: {} };
  }
}
function saveAccounts(obj) {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(obj));
}

// ---------- defaults / utils ----------
function defaultState() {
  return { portfolioValue: 50000, totalProfit: 0, trades: [], roiBaseline: 50000 };
}
const fmtINR = (n) =>
  typeof n === "number" && !Number.isNaN(n)
    ? n.toLocaleString("en-IN", { maximumFractionDigits: 2 })
    : "0";

// ============== APP ==============
export default function App() {
  // -------- AUTH --------
  const [auth, setAuth] = useState({ username: "", pin: "" });
  const [activeUser, setActiveUser] = useState("");
  const [cryptoKey, setCryptoKey] = useState(null);
  const [authBanner, setAuthBanner] = useState("");

  useEffect(() => {
    const acc = loadAccounts();
    if (acc.lastUser) setAuth(function (a) { return { ...a, username: acc.lastUser }; });
  }, []);

  // -------- STATE --------
  const [portfolioValue, setPortfolioValue] = useState(50000);
  const [totalProfit, setTotalProfit] = useState(0);
  const [trades, setTrades] = useState([]); // newest-first; each trade gets {prevHash, hash}
  const [roiBaseline, setRoiBaseline] = useState(50000);

  const [portfolioInput, setPortfolioInput] = useState("");
  const [profitLossInput, setProfitLossInput] = useState("");
  const [noteInput, setNoteInput] = useState("");

  const [banner, setBanner] = useState({ type: "", msg: "" });
  const [confirmClear, setConfirmClear] = useState(false);
  const [lastSavedAt, setLastSavedAt] = useState("");

  // integrity state
  const [chainOK, setChainOK] = useState(true);

  // -------- KPIs --------
  const successRate = useMemo(() => {
    if (trades.length === 0) return 0;
    const wins = trades.filter(function (t) { return t.profitLoss > 0; }).length;
    return Math.round((wins / trades.length) * 100);
  }, [trades]);

  const roiPct = useMemo(() => {
    if (!roiBaseline || roiBaseline <= 0) return 0;
    return Number(((totalProfit / roiBaseline) * 100).toFixed(2));
  }, [totalProfit, roiBaseline]);

  const snapshot = () => ({ portfolioValue, totalProfit, trades, roiBaseline });

  // -------- AUTH ACTIONS --------
  const onCreate = async () => {
    try {
      const username = (auth.username || "").trim();
      const pin = (auth.pin || "").trim();
      if (!username) return setAuthBanner("Enter a username");
      if (!/^\d{4}$/.test(pin)) return setAuthBanner("PIN must be 4 digits");

      const acc = loadAccounts();
      if (acc.users[username]) return setAuthBanner("User already exists");

      const k = await deriveKey(pin);
      const state = defaultState();
      const sealed = await encryptJson(state, k.key);

      acc.users[username] = { saltB64: k.saltB64, ivB64: sealed.ivB64, ctB64: sealed.ctB64 };
      acc.lastUser = username;
      saveAccounts(acc);

      setActiveUser(username);
      setCryptoKey(k.key);
      setAuthBanner("");

      setPortfolioValue(state.portfolioValue);
      setTotalProfit(state.totalProfit);
      setTrades(state.trades);
      setRoiBaseline(state.roiBaseline);
      setChainOK(true);
      flash("ok", "Account created & unlocked");
    } catch {
      setAuthBanner("Create failed");
    }
  };

  const onUnlock = async () => {
    try {
      const username = (auth.username || "").trim();
      const pin = (auth.pin || "").trim();
      if (!username) return setAuthBanner("Enter your username");
      if (!/^\d{4}$/.test(pin)) return setAuthBanner("PIN must be 4 digits");

      const acc = loadAccounts();
      const rec = acc.users[username];
      if (!rec) return setAuthBanner("User not found");

      const k = await deriveKey(pin, rec.saltB64);
      const data = await decryptJson({ ivB64: rec.ivB64, ctB64: rec.ctB64 }, k.key);

      // rebuild hashes just in case older data had none
      const rebuilt = await rebuildChain(data.trades || []);
      setChainOK(rebuilt.ok);

      setActiveUser(username);
      setCryptoKey(k.key);
      setAuthBanner("");
      acc.lastUser = username;
      saveAccounts(acc);

      setPortfolioValue(data.portfolioValue);
      setTotalProfit(data.totalProfit);
      setTrades(rebuilt.tradesWithHashes);
      setRoiBaseline(data.roiBaseline);
      flash("ok", "Unlocked");
    } catch {
      setAuthBanner("Invalid PIN");
    }
  };

  const onLogout = () => {
    setActiveUser("");
    setCryptoKey(null);
    setAuth(function (a) { return { ...a, pin: "" }; });
    setAuthBanner("");
  };

  // -------- SAVE (encrypted per user) --------
  const doEncryptedSave = async () => {
    if (!activeUser || !cryptoKey) return false;
    try {
      const state = snapshot();
      const sealed = await encryptJson(state, cryptoKey);
      const acc = loadAccounts();
      if (!acc.users[activeUser]) acc.users[activeUser] = {};
      acc.users[activeUser].ivB64 = sealed.ivB64;
      acc.users[activeUser].ctB64 = sealed.ctB64;
      if (!acc.users[activeUser].saltB64) {
        const k = await deriveKey(auth.pin);
        acc.users[activeUser].saltB64 = k.saltB64;
      }
      saveAccounts(acc);
      setLastSavedAt(new Date().toLocaleTimeString());
      return true;
    } catch {
      return false;
    }
  };

  // autosave + revalidate chain when state changes (no infinite loops)
useEffect(() => {
  (async function () {
    if (!(activeUser && cryptoKey)) return;

    // Recompute chain to validate integrity
    const rebuilt = await rebuildChain(trades);
    setChainOK(rebuilt.ok);

    // Only update trades if hashes are missing or different
    const needWrite =
      rebuilt.tradesWithHashes.length !== trades.length ||
      rebuilt.tradesWithHashes.some((t, i) =>
        t.hash !== trades[i]?.hash || t.prevHash !== trades[i]?.prevHash
      );

    if (needWrite) {
      setTrades(rebuilt.tradesWithHashes);
      // don't save immediately again; let the next render handle it
      return;
    }

    // If nothing changed, just save encrypted snapshot
    await doEncryptedSave();
  })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [trades, portfolioValue, totalProfit, roiBaseline, activeUser, cryptoKey]);

  // -------- activity / auto-lock (2 minutes) --------
  const LOCK_MS = 2 * 60 * 1000;
  const activityRef = useRef(0);
  const timerRef = useRef(0);

  function resetLockTimer() {
    if (!activeUser) return;
    if (timerRef.current) window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(function () {
      onLogout();
      flash("err", "Auto-locked due to inactivity");
    }, LOCK_MS);
  }

  useEffect(() => {
    if (!activeUser) return;
    const bump = function () { activityRef.current = Date.now(); resetLockTimer(); };
    const vis = function () { if (document.visibilityState === "visible") bump(); };

    window.addEventListener("mousemove", bump);
    window.addEventListener("keydown", bump);
    window.addEventListener("touchstart", bump, { passive: true });
    document.addEventListener("visibilitychange", vis);

    resetLockTimer();

    return () => {
      window.removeEventListener("mousemove", bump);
      window.removeEventListener("keydown", bump);
      window.removeEventListener("touchstart", bump);
      document.removeEventListener("visibilitychange", vis);
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, [activeUser]);

  // -------- UI helpers / actions --------
  const flash = (type, msg) => {
    setBanner({ type, msg });
    window.clearTimeout((flash)._t);
    (flash)._t = window.setTimeout(function () { setBanner({ type: "", msg: "" }); }, 1600);
  };

  const handlePortfolioUpdate = () => {
    const v = parseFloat(portfolioInput);
    if (Number.isNaN(v) || v < 0) {
      flash("err", "Enter a valid portfolio value (≥ 0)");
      return;
    }
    setPortfolioValue(Number(v.toFixed(2)));
    if (trades.length === 0) setRoiBaseline(Number(v.toFixed(2)));
    setPortfolioInput("");
    flash("ok", "Portfolio updated");
  };

  const handleAddTrade = async () => {
    const pnl = parseFloat(profitLossInput);
    if (Number.isNaN(pnl)) {
      flash("err", "Enter a valid Profit/Loss (use negative for loss)");
      return;
    }

    const core = {
      id: Date.now(),
      profitLoss: Number(pnl.toFixed(2)),
      note: (noteInput || "").trim(),
      date: new Date().toISOString().slice(0, 10)
    };
    const prevHash = trades.length > 0 ? trades[0].hash : "";
    const hash = await computeTradeHash(prevHash, core);

    const newTrade = { ...core, prevHash: prevHash, hash: hash };

    setTrades(function (prev) { return [newTrade, ...prev]; }); // newest first
    setTotalProfit(function (p) { return Number((p + newTrade.profitLoss).toFixed(2)); });
    setPortfolioValue(function (p) { return Number((p + newTrade.profitLoss).toFixed(2)); });
    setProfitLossInput("");
    setNoteInput("");
    flash("ok", "Trade added");
  };

  const undoLastTrade = () => {
    if (trades.length === 0) return;
    const latest = trades[0];
    setTrades(function (prev) { return prev.slice(1); });
    setTotalProfit(function (p) { return Number((p - latest.profitLoss).toFixed(2)); });
    setPortfolioValue(function (p) { return Number((p - latest.profitLoss).toFixed(2)); });
    flash("ok", "Last trade undone");
  };

  const clearAll = () => {
    const oldLen = trades.length;
    setTrades([]);
    setTotalProfit(0);
    setConfirmClear(false);
    flash("ok", "Cleared " + oldLen + " trades");
  };

  const exportJSON = () => {
    const data = { ...snapshot(), exportedAt: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "tdash-" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-") + ".json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const importJSON = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async function (e) {
      try {
        const parsed = JSON.parse(String(e.target.result || "{}"));
        if (
          parsed &&
          typeof parsed === "object" &&
          typeof parsed.portfolioValue === "number" &&
          typeof parsed.totalProfit === "number" &&
          Array.isArray(parsed.trades)
        ) {
          // rebuild chain on import
          const rebuilt = await rebuildChain(parsed.trades);
          setPortfolioValue(parsed.portfolioValue);
          setTotalProfit(parsed.totalProfit);
          setTrades(rebuilt.tradesWithHashes);
          if (typeof parsed.roiBaseline === "number") setRoiBaseline(parsed.roiBaseline);
          setChainOK(rebuilt.ok);
          flash("ok", "Imported (revalidated)");
        } else {
          flash("err", "Invalid file format");
        }
      } catch {
        flash("err", "Could not read file");
      }
    };
    reader.readAsText(file);
  };

  const setBaselineToCurrent = () => {
    setRoiBaseline(portfolioValue);
    flash("ok", "ROI baseline set to current portfolio");
  };

  // ---------- MONTHLY SUMMARY ----------
  const monthly = useMemo(() => {
    const map = new Map();
    trades.forEach(function (t) {
      const key = (t.date || "").slice(0, 7) || "Unknown";
      if (!map.has(key)) map.set(key, { pnl: 0, count: 0, wins: 0 });
      const m = map.get(key);
      m.pnl += t.profitLoss;
      m.count += 1;
      if (t.profitLoss > 0) m.wins += 1;
    });
    const arr = Array.from(map.entries()).map(function (pair) {
      const month = pair[0]; const v = pair[1];
      return { month: month, pnl: Number(v.pnl.toFixed(2)), trades: v.count, winPct: v.count ? Math.round((v.wins / v.count) * 100) : 0 };
    }).sort(function (a, b) { return a.month > b.month ? 1 : -1; });
    return arr;
  }, [trades]);

  const exportMonthlyCSV = () => {
    const header = "Month,Trades,Win%,P&L (INR)\n";
    const rows = monthly.map(function (m) { return [m.month, m.trades, m.winPct, m.pnl].join(","); });
    const csv = header + rows.join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "tdash-monthly.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  // ---------- Monthly bar chart ----------
  const monthChartWrapRef = useRef(null);
  const monthCanvasRef = useRef(null);

  const drawMonthlyChart = () => {
    const wrap = monthChartWrapRef.current;
    const canvas = monthCanvasRef.current;
    if (!wrap || !canvas) return;

    const dpr = window.devicePixelRatio || 1;
    const width = wrap.clientWidth;
    const height = Math.max(220, Math.floor(width * 0.5));
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);

    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    ctx.fillStyle = "rgba(2,6,23,0.65)";
    ctx.fillRect(0, 0, width, height);

    if (monthly.length === 0) {
      ctx.fillStyle = "#94a3b8";
      ctx.font = "14px Arial";
      ctx.fillText("No data yet — add trades to see monthly progress.", 12, 24);
      return;
    }

    const pad = { l: 44, r: 18, t: 16, b: 48 };
    const plotW = width - pad.l - pad.r;
    const plotH = height - pad.t - pad.b;

    const minY = Math.min(0, Math.min.apply(null, monthly.map(function (m) { return m.pnl; })));
    const maxY = Math.max(0, Math.max.apply(null, monthly.map(function (m) { return m.pnl; })));
    const yRange = maxY - minY || 1;

    const yFor = function (val) { return pad.t + plotH - ((val - minY) / yRange) * plotH; };

    // axes
    ctx.strokeStyle = "rgba(255,255,255,0.15)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.l, pad.t);
    ctx.lineTo(pad.l, pad.t + plotH);
    ctx.lineTo(pad.l + plotW, pad.t + plotH);
    ctx.stroke();

    // zero line
    const y0 = yFor(0);
    ctx.strokeStyle = "rgba(255,255,255,0.2)";
    ctx.beginPath();
    ctx.moveTo(pad.l, y0);
    ctx.lineTo(pad.l + plotW, y0);
    ctx.stroke();

    // y grid & labels
    ctx.fillStyle = "#a3b2c7";
    ctx.font = "12px Arial";
    const gridLines = 4;
    for (let i = 0; i <= gridLines; i++) {
      const ratio = i / gridLines;
      const y = pad.t + plotH - ratio * plotH;
      ctx.strokeStyle = "rgba(255,255,255,0.08)";
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + plotW, y);
      ctx.stroke();
      const val = minY + ratio * yRange;
      const label = (val >= 0 ? "+₹" : "-₹") + Math.abs(val).toLocaleString("en-IN");
      ctx.fillText(label, 6, y + 4);
    }

    // bars
    const n = monthly.length;
    const gap = 6;
    const barFullW = Math.max(10, plotW / Math.max(1, n));
    const barW = Math.max(4, barFullW - gap);

    monthly.forEach(function (m, i) {
      const x = pad.l + i * barFullW + gap / 2;
      const y = yFor(m.pnl);
      const color = m.pnl >= 0 ? "#22c55e" : "#ef4444";
      ctx.fillStyle = color;

      if (m.pnl >= 0) {
        const h = Math.max(1, y0 - y);
        ctx.fillRect(x, y, barW, h);
      } else {
        const h = Math.max(1, y - y0);
        ctx.fillRect(x, y0, barW, h);
      }

      ctx.fillStyle = "#a3b2c7";
      ctx.font = "11px Arial";
      ctx.fillText(m.month, x - 6, pad.t + plotH + 18);
    });
  };

  useEffect(() => { drawMonthlyChart(); /* eslint-disable-next-line */ }, [monthly]);

  // ---------- Per-trade bar chart ----------
  const tradeChartWrapRef = useRef(null);
  const tradeCanvasRef = useRef(null);
  const barPoints = useMemo(() => {
    if (trades.length === 0) return [];
    const chrono = [...trades].reverse();
    return chrono.map(function (t, idx) { return { idx: idx, date: t.date, pnl: t.profitLoss }; });
  }, [trades]);

  const drawTradeChart = () => {
    const wrap = tradeChartWrapRef.current;
    const canvas = tradeCanvasRef.current;
    if (!wrap || !canvas) return;

    const dpr = window.devicePixelRatio || 1;
    const width = wrap.clientWidth;
    const height = Math.max(240, Math.floor(width * 0.5));
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);

    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    ctx.fillStyle = "rgba(2,6,23,0.65)";
    ctx.fillRect(0, 0, width, height);

    if (barPoints.length === 0) {
      ctx.fillStyle = "#94a3b8";
      ctx.font = "14px Arial";
      ctx.fillText("No trades yet — add a trade to see the bar chart.", 12, 24);
      return;
    }

    const pad = { l: 44, r: 18, t: 16, b: 36 };
    const plotW = width - pad.l - pad.r;
    const plotH = height - pad.t - pad.b;

    const minY = Math.min(0, Math.min.apply(null, barPoints.map(function (p) { return p.pnl; })));
    const maxY = Math.max(0, Math.max.apply(null, barPoints.map(function (p) { return p.pnl; })));
    const yRange = maxY - minY || 1;
    const yFor = function (val) { return pad.t + plotH - ((val - minY) / yRange) * plotH; };

    ctx.strokeStyle = "rgba(255,255,255,0.15)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.l, pad.t);
    ctx.lineTo(pad.l, pad.t + plotH);
    ctx.lineTo(pad.l + plotW, pad.t + plotH);
    ctx.stroke();

    const y0 = yFor(0);
    ctx.strokeStyle = "rgba(255,255,255,0.2)";
    ctx.beginPath();
    ctx.moveTo(pad.l, y0);
    ctx.lineTo(pad.l + plotW, y0);
    ctx.stroke();

    ctx.fillStyle = "#a3b2c7";
    ctx.font = "12px Arial";
    const gridLines = 4;
    for (let i = 0; i <= gridLines; i++) {
      const ratio = i / gridLines;
      const y = pad.t + plotH - ratio * plotH;
      ctx.strokeStyle = "rgba(255,255,255,0.08)";
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + plotW, y);
      ctx.stroke();
      const val = minY + ratio * yRange;
      const label = (val >= 0 ? "+₹" : "-₹") + Math.abs(val).toLocaleString("en-IN");
      ctx.fillText(label, 6, y + 4);
    }

    const n = barPoints.length;
    const gap = 4;
    const barFullW = Math.max(6, plotW / Math.max(1, n));
    const barW = Math.max(2, barFullW - gap);

    barPoints.forEach(function (p, i) {
      const x = pad.l + i * barFullW + gap / 2;
      const y = yFor(p.pnl);
      const color = p.pnl >= 0 ? "#22c55e" : "#ef4444";
      ctx.fillStyle = color;

      if (p.pnl >= 0) {
        const h = Math.max(1, y0 - y);
        ctx.fillRect(x, y, barW, h);
      } else {
        const h = Math.max(1, y - y0);
        ctx.fillRect(x, y0, barW, h);
      }
    });

    ctx.fillStyle = "#a3b2c7";
    ctx.font = "11px Arial";
    const firstIdx = 0;
    const lastIdx = n - 1;
    const midIdx = Math.floor(lastIdx / 2);
    const idxToX = function (idx) { return pad.l + idx * barFullW + barFullW / 2; };
    const labelAt = function (idx, text) {
      const x = idxToX(idx);
      const y = pad.t + plotH + 20;
      ctx.fillText(text, Math.max(pad.l, Math.min(x - 18, width - 60)), y);
    };
    labelAt(firstIdx, barPoints[firstIdx].date);
    labelAt(midIdx, barPoints[midIdx].date);
    labelAt(lastIdx, barPoints[lastIdx].date);
  };

  useEffect(() => { drawTradeChart(); /* eslint-disable-next-line */ }, [barPoints]);

  // ---------- styles ----------
  const s = {
    page: { minHeight: "100vh", background: "linear-gradient(180deg, #0f172a 0%, #0b1220 45%, #0b1327 100%)", color: "#e5e7eb", fontFamily: "Inter, system-ui, -apple-system, Arial", padding: 20 },
    container: { maxWidth: 980, margin: "0 auto" },
    header: { textAlign: "center", padding: "16px 14px", borderRadius: 12, background: "linear-gradient(90deg, rgba(25,118,210,0.25), rgba(66,165,245,0.25))", border: "1px solid rgba(255,255,255,0.08)", backdropFilter: "blur(6px)", boxShadow: "0 10px 24px rgba(0,0,0,0.25)", marginBottom: 12 },
    h1: { margin: 0, fontSize: 26, fontWeight: 700 },
    sub: { margin: "6px 0 0 0", color: "#cbd5e1", fontSize: 13 },

    banner: { margin: "8px auto 0", maxWidth: 980, padding: "8px 12px", borderRadius: 10, textAlign: "center",
      background: banner.type === "ok" ? "rgba(34,197,94,.15)" : "rgba(239,68,68,.15)",
      border: "1px solid " + (banner.type === "ok" ? "rgba(34,197,94,.35)" : "rgba(239,68,68,.35)"),
      color: banner.type === "ok" ? "#86efac" : "#fca5a5", fontWeight: 600, transition: "opacity .2s", opacity: banner.msg ? 1 : 0 },

    cardRow: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginTop: 14, marginBottom: 10 },
    card: { background: "rgba(15,23,42,0.55)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12, padding: 12, boxShadow: "0 6px 16px rgba(0,0,0,0.25)", minHeight: 96 },
    label: { color: "#a3b2c7", fontSize: 12, marginBottom: 6 },
    value: { fontSize: 20, fontWeight: 700 },

    row: { display: "flex", gap: 8, flexWrap: "wrap" },
    input: { flex: "1 1 220px", minWidth: 0, padding: "10px 12px", borderRadius: 10, border: "1px solid rgba(255,255,255,0.12)", background: "rgba(2,6,23,0.65)", color: "#e5e7eb", outline: "none", boxSizing: "border-box" },
    btn: { flex: "0 1 160px", padding: "10px 14px", borderRadius: 10, border: "1px solid rgba(255,255,255,0.12)", background: "linear-gradient(180deg, rgba(25,118,210,0.9), rgba(17,94,163,0.9))", color: "#fff", cursor: "pointer", fontWeight: 600, letterSpacing: 0.3, boxSizing: "border-box" },
    btnGhost: { flex: "0 1 160px", padding: "10px 14px", borderRadius: 10, border: "1px solid rgba(255,255,255,0.12)", background: "transparent", color: "#cbd5e1", cursor: "pointer", fontWeight: 600, letterSpacing: 0.3, boxSizing: "border-box" },

    section: { background: "rgba(15,23,42,0.55)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12, padding: 12, boxShadow: "0 6px 16px rgba(0,0,0,0.25)", marginTop: 10 },
    sectionTitle: { margin: "0 0 10px 0", fontSize: 17 },

    tradeItem: { padding: "10px 12px", borderRadius: 10, background: "rgba(2,6,23,0.45)", border: "1px solid rgba(255,255,255,0.08)", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" },
    note: { color: "#a3b2c7", fontSize: 12, marginTop: 6 },
    badge: { fontSize: 12, padding: "2px 8px", borderRadius: 999, border: "1px solid rgba(255,255,255,0.12)", marginLeft: 8 },
    green: { color: "#22c55e", fontWeight: 700 },
    red: { color: "#ef4444", fontWeight: 700 },

    toolbar: { display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8, marginBottom: 6, alignItems: "center" },
    saveHint: { color: "#94a3b8", fontSize: 12 },

    chartWrap: { width: "100%", borderRadius: 12, border: "1px solid rgba(255,255,255,0.08)", background: "rgba(2,6,23,0.45)", padding: 8, boxShadow: "0 6px 16px rgba(0,0,0,0.25)", marginTop: 10, overflowX: "auto" },

    authWrap: { maxWidth: 420, margin: "10vh auto 0", padding: 16, borderRadius: 12, background: "rgba(15,23,42,0.55)", border: "1px solid rgba(255,255,255,0.08)", boxShadow: "0 10px 24px rgba(0,0,0,0.25)", textAlign: "center" },
    authTitle: { margin: "0 0 6px 0", fontSize: 24, fontWeight: 700 },
    authInput: { width: "100%", padding: "10px 12px", borderRadius: 10, border: "1px solid rgba(255,255,255,0.12)", background: "rgba(2,6,23,0.65)", color: "#e5e7eb", outline: "none", boxSizing: "border-box", marginTop: 8 },
    authBtnRow: { display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }
  };

  // ---------- AUTH SCREEN ----------
  if (!activeUser) {
    return (
      <div style={s.page}>
        <div style={s.authWrap}>
          <div style={s.authTitle}>Trading Dashboard</div>
          <div style={{ color: "#cbd5e1", marginBottom: 6 }}>Developed by Ansh Maheshwari</div>
          {authBanner ? (
            <div style={{ margin: "8px 0", padding: "8px 12px", borderRadius: 10,
              background: "rgba(239,68,68,.15)", border: "1px solid rgba(239,68,68,.35)", color: "#fca5a5", fontWeight: 600 }}>
              {authBanner}
            </div>
          ) : null}
          <input
            style={s.authInput}
            placeholder="Username"
            value={auth.username}
            onChange={(e) => setAuth({ ...auth, username: e.target.value })}
          />
          <input
            style={s.authInput}
            placeholder="4-digit PIN"
            inputMode="numeric"
            maxLength={4}
            value={auth.pin}
            onChange={(e) => {
              if (/^\d{0,4}$/.test(e.target.value)) setAuth({ ...auth, pin: e.target.value });
            }}
          />
          <div style={s.authBtnRow}>
            <button style={s.btn} onClick={onCreate}>Create Account</button>
            <button style={s.btnGhost} onClick={onUnlock}>Unlock</button>
          </div>
        </div>
      </div>
    );
  }

  // ---------- MAIN APP ----------
  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.header}>
          <h1 style={s.h1}>Trading Dashboard</h1>
          <p style={s.sub}>Developed by Ansh Maheshwari</p>
          <div style={{ marginTop: 8, fontSize: 12, color: "#94a3b8" }}>
            Logged in as <strong>{activeUser}</strong> • {lastSavedAt ? "Last saved " + lastSavedAt : "Saving…"} • Integrity:{" "}
            <span style={{ color: chainOK ? "#86efac" : "#fca5a5", fontWeight: 700 }}>
              {chainOK ? "OK" : "⚠ compromised"}
            </span>
          </div>
          <div style={{ marginTop: 8 }}>
            <button style={s.btnGhost} onClick={onLogout}>Logout / Switch user</button>
          </div>
        </div>

        {/* banner */}
        <div style={s.banner}>{banner.msg}</div>

        {/* KPIs */}
        <div style={s.cardRow}>
          <div style={s.card}>
            <div style={s.label}>Portfolio Value</div>
            <div style={s.value}>₹ {fmtINR(portfolioValue)}</div>
            <div style={{ ...s.row, marginTop: 10 }}>
              <input
                style={s.input}
                type="number"
                placeholder="Set portfolio value"
                value={portfolioInput}
                onChange={(e) => setPortfolioInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handlePortfolioUpdate()}
              />
              <button style={s.btn} onClick={handlePortfolioUpdate}>Update</button>
            </div>
          </div>

          <div style={s.card}>
            <div style={s.label}>Total Profit</div>
            <div style={{ ...s.value, color: totalProfit >= 0 ? s.green.color : s.red.color }}>
              ₹ {fmtINR(totalProfit)}
            </div>
          </div>

          <div style={s.card}>
            <div style={s.label}>Total Trades</div>
            <div style={s.value}>{trades.length}</div>
          </div>

          <div style={s.card}>
            <div style={s.label}>Success Rate</div>
            <div style={s.value}>{successRate}%</div>
          </div>

          <div style={s.card}>
            <div style={s.label}>ROI</div>
            <div style={s.value}>
              {roiPct}% <span style={{ fontSize: 12, color: "#a3b2c7" }}>(baseline: ₹ {fmtINR(roiBaseline)})</span>
            </div>
            <div style={{ ...s.row, marginTop: 10 }}>
              <button style={s.btnGhost} onClick={setBaselineToCurrent}>🧭 Set ROI baseline = current</button>
            </div>
          </div>
        </div>

        {/* toolbar */}
       {/* toolbar */}
<div style={s.toolbar}>
  <button
    style={s.btnGhost}
    onClick={undoLastTrade}
    disabled={trades.length === 0}
  >
    ⏪ Undo last
  </button>

  {!confirmClear ? (
    <button
      style={s.btnGhost}
      onClick={() => setConfirmClear(true)}
      disabled={trades.length === 0}
    >
      🧹 Clear all
    </button>
  ) : (
    <>
      <span>Confirm clear?</span>
      <button
        style={s.btn}
        onClick={clearAll}               // ✅ this triggers the wipe
      >
        Yes
      </button>
      <button
        style={s.btnGhost}
        onClick={() => setConfirmClear(false)}
      >
        No
      </button>
    </>
  )}

  <button style={s.btnGhost} onClick={exportJSON}>⬇ Export JSON</button>
  <label style={{ display: "inline-block", color: "#cbd5e1" }}>
    ⬆ Import JSON
    <input
      type="file"
      accept="application/json"
      style={{ display: "none" }}
      onChange={(e) => importJSON(e.target.files && e.target.files[0])}
    />
  </label>

  <button
    style={s.btnGhost}
    onClick={async () => {
      const ok = await doEncryptedSave();
      flash(ok ? "ok" : "err", ok ? "Saved" : "Save failed");
    }}
  >
    💾 Save now
  </button>
</div>

       {/* ADD TRADE */}
        <div style={s.section}>
          <h3 style={s.sectionTitle}>Add a Trade</h3>
          <div style={{ ...s.row, marginBottom: 10 }}>
            <input
              style={s.input}
              type="number"
              placeholder="Profit (+) or Loss (-) e.g. 500 or -300"
              value={profitLossInput}
              onChange={(e) => setProfitLossInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAddTrade()}
            />
            <button style={s.btn} onClick={handleAddTrade}>Add Trade</button>
          </div>
          <input
            style={s.input}
            type="text"
            placeholder="(Optional) Note — why you took this trade"
            value={noteInput}
            onChange={(e) => setNoteInput(e.target.value)}
          />
        </div>
      
      
        {/* MONTHLY PROGRESS */}
        <div style={s.section}>
          <h3 style={s.sectionTitle}>Monthly Progress</h3>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "separate", borderSpacing: "0 6px" }}>
              <thead>
                <tr style={{ textAlign: "left", color: "#a3b2c7" }}>
                  <th style={{ padding: "6px 8px" }}>Month</th>
                  <th style={{ padding: "6px 8px" }}>Trades</th>
                  <th style={{ padding: "6px 8px" }}>Win%</th>
                  <th style={{ padding: "6px 8px" }}>P&L (₹)</th>
                </tr>
              </thead>
              <tbody>
                {monthly.length === 0 ? (
                  <tr><td style={{ padding: "8px 8px", color: "#a3b2c7" }} colSpan={4}>No data yet</td></tr>
                ) : (
                  monthly.map(function (m) {
                    return (
                      <tr key={m.month}>
                        <td style={{ padding: "8px 8px" }}>{m.month}</td>
                        <td style={{ padding: "8px 8px" }}>{m.trades}</td>
                        <td style={{ padding: "8px 8px" }}>{m.winPct}%</td>
                        <td style={{ padding: "8px 8px", color: m.pnl >= 0 ? s.green.color : s.red.color, fontWeight: 700 }}>
                          {(m.pnl >= 0 ? "+" : "-") + "₹ " + fmtINR(Math.abs(m.pnl))}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button style={s.btnGhost} onClick={exportMonthlyCSV}>⬇ Export Monthly CSV</button>
          </div>

          <div ref={monthChartWrapRef} style={s.chartWrap}>
            <canvas ref={monthCanvasRef} />
          </div>
        </div>

       

        {/* RECENT TRADES */}
        <div style={s.section}>
          <h3 style={s.sectionTitle}>Recent Trades</h3>
          {trades.length === 0 ? (
            <div style={{ color: "#a3b2c7" }}>No trades yet</div>
          ) : (
            trades.map(function (t) {
              return (
                <div key={t.id} style={s.tradeItem}>
                  <div>
                    <div>
                      <strong>{"Trade #" + t.id}</strong> • {t.date}
                      <span style={{ ...s.badge, marginLeft: 8, color: t.profitLoss >= 0 ? s.green.color : s.red.color }}>
                        {t.profitLoss >= 0 ? "WIN" : "LOSS"}
                      </span>
                    </div>
                    {t.note ? <div style={s.note}>{t.note}</div> : null}
                    {/* small hash preview (last 8 chars) */}
                    <div style={{ color: "#94a3b8", fontSize: 11, marginTop: 4 }}>
                      h:{t.hash ? t.hash.slice(-8) : ""} • prev:{t.prevHash ? t.prevHash.slice(-8) : ""}
                    </div>
                  </div>
                  <div style={t.profitLoss >= 0 ? s.green : s.red}>
                    {(t.profitLoss >= 0 ? "+" : "-") + "₹ " + fmtINR(Math.abs(t.profitLoss))}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* PER-TRADE BAR CHART */}
        <div style={s.section}>
          <h3 style={s.sectionTitle}>Trade P&L — Bar Chart</h3>
          <div ref={tradeChartWrapRef} style={s.chartWrap}>
            <canvas ref={tradeCanvasRef} />
          </div>
        </div>
      </div>
    </div>
  );
}