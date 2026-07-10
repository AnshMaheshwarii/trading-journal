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
      ctx.font = "14px Inter, Arial";
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
    ctx.font = "12px Inter, Arial";
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
      ctx.font = "11px Inter, Arial";
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
      ctx.font = "14px Inter, Arial";
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
    ctx.font = "12px Inter, Arial";
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
    ctx.font = "11px Inter, Arial";
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

  // ---------- design tokens ----------
  const FONT_BODY = "'Inter', -apple-system, 'Segoe UI', system-ui, sans-serif";
  const FONT_DISPLAY = "'Plus Jakarta Sans', 'Inter', -apple-system, sans-serif";
  const NUM = { fontFamily: FONT_DISPLAY, fontVariantNumeric: "tabular-nums", fontFeatureSettings: "'tnum' 1, 'ss01' 1" };

  const C = {
    bg: "#07080c",
    surface: "#0d0f14",
    surfaceAlt: "#12141b",
    sidebar: "#090a0f",
    border: "rgba(255,255,255,0.06)",
    borderStrong: "rgba(255,255,255,0.13)",
    text: "#eceef2",
    textDim: "#8b93a7",
    textFaint: "#565f74",
    accent: "#5b8def",
    accentDim: "rgba(91,141,239,0.13)",
    green: "#2ecc84",
    greenDim: "rgba(46,204,132,0.11)",
    red: "#f5586b",
    redDim: "rgba(245,88,107,0.11)"
  };

  // ---------- styles ----------
  const s = {
    shell: { minHeight: "100vh", background: C.bg, color: C.text, fontFamily: FONT_BODY, display: "flex", WebkitFontSmoothing: "antialiased" },

    // ---- sidebar ----
    sidebar: { width: 240, flexShrink: 0, background: C.sidebar, borderRight: "1px solid " + C.border, display: "flex", flexDirection: "column", padding: "24px 14px", position: "sticky", top: 0, height: "100vh" },

    sideSectionLabel: { fontSize: 10.5, fontWeight: 700, letterSpacing: "0.09em", color: C.textFaint, textTransform: "uppercase", margin: "22px 8px 8px" },

    userCard: { padding: "13px 12px", borderRadius: 12, background: C.surfaceAlt, border: "1px solid " + C.border, display: "flex", alignItems: "center", gap: 10 },
    userAvatar: { width: 34, height: 34, borderRadius: "50%", background: C.accentDim, color: C.accent, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 12.5, flexShrink: 0, fontFamily: FONT_DISPLAY },
    userName: { fontSize: 13.5, fontWeight: 700, letterSpacing: "-0.005em" },
    userMeta: { fontSize: 11, color: C.textFaint, marginTop: 2 },

    integrityRow: { marginTop: 10, display: "flex", alignItems: "center", gap: 8, padding: "9px 11px", borderRadius: 10, background: C.surfaceAlt, border: "1px solid " + C.border, fontSize: 11.5 },
    dot: (ok) => ({ width: 6, height: 6, borderRadius: "50%", background: ok ? C.green : C.red, flexShrink: 0, boxShadow: "0 0 8px " + (ok ? C.green : C.red) }),

    sideBtn: { display: "flex", alignItems: "center", gap: 9, width: "100%", padding: "9px 10px", borderRadius: 8, border: "1px solid transparent", background: "transparent", color: C.textDim, cursor: "pointer", fontSize: 12.5, fontWeight: 500, textAlign: "left", fontFamily: FONT_BODY, letterSpacing: "-0.005em" },
    sideBtnDanger: { color: "#e58991" },

    sideFooter: { marginTop: "auto", paddingTop: 16, borderTop: "1px solid " + C.border },

    // ---- main ----
    main: { flex: 1, minWidth: 0, padding: "26px 32px 64px" },
    maxW: { maxWidth: 1260, margin: "0 auto" },

    topBar: { display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, flexWrap: "wrap", marginBottom: 22 },
    pageTitle: { fontFamily: FONT_DISPLAY, fontSize: 24, fontWeight: 700, letterSpacing: "-0.025em", margin: 0 },
    pageSub: { fontSize: 13, color: C.textFaint, margin: "5px 0 0", letterSpacing: "-0.005em" },

    saveChip: { fontSize: 11.5, color: C.textFaint, background: C.surfaceAlt, border: "1px solid " + C.border, padding: "7px 13px", borderRadius: 999, display: "inline-flex", alignItems: "center", gap: 7, fontWeight: 500 },

    banner: (type) => ({ padding: "11px 15px", borderRadius: 10, textAlign: "center", fontSize: 13, fontWeight: 500,
      background: type === "ok" ? C.greenDim : C.redDim,
      border: "1px solid " + (type === "ok" ? "rgba(46,204,132,.3)" : "rgba(245,88,107,.3)"),
      color: type === "ok" ? C.green : C.red, marginBottom: 18 }),

    // hero + kpi
    heroGrid: { display: "grid", gridTemplateColumns: "1.25fr 1fr 1fr", gap: 14, marginBottom: 14 },
    hero: { background: "linear-gradient(160deg, rgba(91,141,239,0.12), rgba(13,15,20,0.3))", border: "1px solid " + C.border, borderRadius: 18, padding: "22px 22px 20px", display: "flex", flexDirection: "column", justifyContent: "space-between" },
    heroLabel: { fontSize: 11.5, fontWeight: 600, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.06em" },
    heroValue: { ...NUM, fontSize: 36, fontWeight: 700, letterSpacing: "-0.03em", margin: "10px 0 16px", lineHeight: 1 },

    kpiGrid: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 14 },
    kpiCard: { background: C.surface, border: "1px solid " + C.border, borderRadius: 14, padding: "16px 17px", display: "flex", flexDirection: "column", justifyContent: "center" },
    kpiLabel: { fontSize: 10.5, fontWeight: 600, color: C.textFaint, textTransform: "uppercase", letterSpacing: "0.06em" },
    kpiValue: { ...NUM, fontSize: 22, fontWeight: 700, marginTop: 7, letterSpacing: "-0.02em", lineHeight: 1.1 },
    kpiFoot: { fontSize: 11, color: C.textFaint, marginTop: 5, letterSpacing: "-0.005em" },

    // generic panel
    panel: { background: C.surface, border: "1px solid " + C.border, borderRadius: 16, padding: 20 },
    panelHead: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap", marginBottom: 16 },
    panelTitleWrap: { display: "flex", alignItems: "center", gap: 9 },
    panelIcon: { width: 25, height: 25, borderRadius: 7, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12.5, flexShrink: 0 },
    panelTitle: { fontFamily: FONT_DISPLAY, fontSize: 14.5, fontWeight: 700, margin: 0, letterSpacing: "-0.015em" },
    panelSub: { fontSize: 11.5, color: C.textFaint, margin: "2px 0 0", letterSpacing: "-0.005em" },

    // inputs / buttons
    field: { flex: "1 1 200px", minWidth: 0, padding: "10px 13px", borderRadius: 9, border: "1px solid " + C.border, background: "#05060a", color: C.text, outline: "none", fontSize: 13, fontFamily: FONT_BODY, boxSizing: "border-box", letterSpacing: "-0.005em" },
    row: { display: "flex", gap: 8, flexWrap: "wrap" },
    btnPrimary: { padding: "9px 15px", borderRadius: 9, border: "1px solid rgba(91,141,239,0.5)", background: C.accent, color: "#07080c", cursor: "pointer", fontWeight: 600, fontSize: 12.5, whiteSpace: "nowrap", fontFamily: FONT_BODY, letterSpacing: "-0.005em" },
    btnGhost: { padding: "9px 14px", borderRadius: 9, border: "1px solid " + C.border, background: "transparent", color: C.textDim, cursor: "pointer", fontWeight: 500, fontSize: 12, whiteSpace: "nowrap", fontFamily: FONT_BODY, letterSpacing: "-0.005em" },
    btnGhostSmall: { padding: "6px 10px", borderRadius: 7, border: "1px solid " + C.border, background: "transparent", color: C.textDim, cursor: "pointer", fontWeight: 500, fontSize: 11, whiteSpace: "nowrap", fontFamily: FONT_BODY },

    // workspace grid
    workspace: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 16, alignItems: "start" },

    chartWrap: { width: "100%", borderRadius: 12, border: "1px solid " + C.border, background: "#05060a", padding: 8, marginTop: 14, overflowX: "auto" },

    tradesScroll: { maxHeight: 380, overflowY: "auto", paddingRight: 4, display: "flex", flexDirection: "column", gap: 8 },
    tradeItem: { padding: "12px 14px", borderRadius: 11, background: "#05060a", border: "1px solid " + C.border, display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" },
    note: { color: C.textDim, fontSize: 12, marginTop: 5, letterSpacing: "-0.005em" },
    badge: (win) => ({ fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999, marginLeft: 8, background: win ? C.greenDim : C.redDim, color: win ? C.green : C.red, letterSpacing: "0.04em" }),
    green: { ...NUM, color: C.green, fontWeight: 700 },
    red: { ...NUM, color: C.red, fontWeight: 700 },

    table: { width: "100%", borderCollapse: "separate", borderSpacing: "0 6px", fontSize: 13 },
    th: { padding: "6px 10px", textAlign: "left", fontSize: 10, fontWeight: 700, color: C.textFaint, textTransform: "uppercase", letterSpacing: "0.05em" },
    td: { padding: "10px 10px", background: "#05060a", letterSpacing: "-0.005em" },

    // auth
    authShell: { minHeight: "100vh", background: C.bg, display: "flex", alignItems: "center", justifyContent: "center", color: C.text, fontFamily: FONT_BODY, WebkitFontSmoothing: "antialiased", padding: 24 },
    authCard: { width: "100%", maxWidth: 360 },
    authInput: { width: "100%", padding: "12px 14px", borderRadius: 10, border: "1px solid " + C.border, background: "#05060a", color: C.text, outline: "none", boxSizing: "border-box", marginTop: 10, fontSize: 14, fontFamily: FONT_BODY, letterSpacing: "-0.005em" }
  };

  const FontImport = () => (
    <style>{"@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');"}</style>
  );

  // ---------- AUTH SCREEN ----------
  if (!activeUser) {
    return (
      <div style={s.authShell}>
        <FontImport />
        <div style={s.authCard}>
          <div style={{ fontFamily: FONT_DISPLAY, fontSize: 24, fontWeight: 700, letterSpacing: "-0.02em", marginBottom: 5 }}>Welcome back</div>
          <div style={{ color: C.textFaint, fontSize: 13, marginBottom: 20, letterSpacing: "-0.005em" }}>Sign in to your encrypted journal</div>

          {authBanner ? <div style={s.banner("err")}>{authBanner}</div> : null}

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
          <div style={{ display: "flex", gap: 10, marginTop: 18 }}>
            <button style={{ ...s.btnPrimary, flex: 1, padding: "11px 15px", fontSize: 13 }} onClick={onCreate}>Create Account</button>
            <button style={{ ...s.btnGhost, flex: 1, padding: "11px 15px", fontSize: 13 }} onClick={onUnlock}>Unlock</button>
          </div>
        </div>
      </div>
    );
  }

  // ---------- MAIN APP ----------
  return (
    <div style={s.shell}>
      <FontImport />

      {/* SIDEBAR */}
      <aside style={s.sidebar}>
        <div style={s.sideSectionLabel}>Account</div>
        <div style={s.userCard}>
          <div style={s.userAvatar}>{activeUser.slice(0, 2).toUpperCase()}</div>
          <div>
            <div style={s.userName}>{activeUser}</div>
            <div style={s.userMeta}>{lastSavedAt ? "Saved " + lastSavedAt : "Saving…"}</div>
          </div>
        </div>

        <div style={s.integrityRow}>
          <span style={s.dot(chainOK)} />
          <span style={{ color: chainOK ? C.green : C.red, fontWeight: 600 }}>
            {chainOK ? "Chain verified" : "Chain compromised"}
          </span>
        </div>

        <div style={s.sideSectionLabel}>Data</div>
        <button style={s.sideBtn} onClick={undoLastTrade} disabled={trades.length === 0}>
          ⏪ Undo last trade
        </button>
        <button style={s.sideBtn} onClick={exportJSON}>⬇ Export JSON</button>
        <label style={s.sideBtn}>
          ⬆ Import JSON
          <input
            type="file"
            accept="application/json"
            style={{ display: "none" }}
            onChange={(e) => importJSON(e.target.files && e.target.files[0])}
          />
        </label>
        <button
          style={s.sideBtn}
          onClick={async () => {
            const ok = await doEncryptedSave();
            flash(ok ? "ok" : "err", ok ? "Saved" : "Save failed");
          }}
        >
          💾 Save now
        </button>

        {!confirmClear ? (
          <button style={{ ...s.sideBtn, ...s.sideBtnDanger }} onClick={() => setConfirmClear(true)} disabled={trades.length === 0}>
            🧹 Clear all trades
          </button>
        ) : (
          <div style={{ padding: "9px 10px", display: "flex", flexDirection: "column", gap: 7 }}>
            <span style={{ fontSize: 11.5, color: C.textDim }}>Clear all trades?</span>
            <div style={{ display: "flex", gap: 6 }}>
              <button style={{ ...s.btnGhostSmall, color: C.red, borderColor: "rgba(245,88,107,.4)" }} onClick={clearAll}>Yes, clear</button>
              <button style={s.btnGhostSmall} onClick={() => setConfirmClear(false)}>Cancel</button>
            </div>
          </div>
        )}

        <div style={s.sideFooter}>
          <button style={{ ...s.sideBtn, ...s.sideBtnDanger }} onClick={onLogout}>
            ⏻ Logout / Switch user
          </button>
        </div>
      </aside>

      {/* MAIN */}
      <main style={s.main}>
        <div style={s.maxW}>

          <div style={s.topBar}>
            <div>
              <h1 style={s.pageTitle}>Dashboard</h1>
              <p style={s.pageSub}>Live overview of your portfolio &amp; trading performance</p>
            </div>
            <div style={s.saveChip}>
              <span style={s.dot(chainOK)} />
              {lastSavedAt ? "Last saved " + lastSavedAt : "Saving…"}
            </div>
          </div>

          {banner.msg ? <div style={s.banner(banner.type)}>{banner.msg}</div> : null}

          {/* HERO + KPI ROW */}
          <div style={s.heroGrid}>
            <div style={s.hero}>
              <div>
                <div style={s.heroLabel}>Portfolio Value</div>
                <div style={s.heroValue}>₹{fmtINR(portfolioValue)}</div>
              </div>
              <div style={s.row}>
                <input
                  style={s.field}
                  type="number"
                  placeholder="Set portfolio value"
                  value={portfolioInput}
                  onChange={(e) => setPortfolioInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handlePortfolioUpdate()}
                />
                <button style={s.btnPrimary} onClick={handlePortfolioUpdate}>Update</button>
              </div>
            </div>

            <div style={s.kpiGrid}>
              <div style={s.kpiCard}>
                <div style={s.kpiLabel}>Total Profit</div>
                <div style={{ ...s.kpiValue, color: totalProfit >= 0 ? C.green : C.red }}>
                  ₹{fmtINR(totalProfit)}
                </div>
              </div>
              <div style={s.kpiCard}>
                <div style={s.kpiLabel}>Total Trades</div>
                <div style={s.kpiValue}>{trades.length}</div>
              </div>
              <div style={s.kpiCard}>
                <div style={s.kpiLabel}>Success Rate</div>
                <div style={s.kpiValue}>{successRate}%</div>
              </div>
              <div style={s.kpiCard}>
                <div style={s.kpiLabel}>ROI</div>
                <div style={s.kpiValue}>{roiPct}%</div>
                <div style={s.kpiFoot}>baseline ₹{fmtINR(roiBaseline)}</div>
              </div>
            </div>

            <div style={{ ...s.panel, display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <div>
                <div style={s.panelIcon}>🧭</div>
                <div style={{ fontFamily: FONT_DISPLAY, fontSize: 13.5, fontWeight: 700, marginTop: 12, letterSpacing: "-0.01em" }}>ROI Baseline</div>
                <p style={{ fontSize: 11.5, color: C.textFaint, marginTop: 5, lineHeight: 1.55, letterSpacing: "-0.005em" }}>
                  Recalculate ROI against your current portfolio value.
                </p>
              </div>
              <button style={{ ...s.btnGhost, width: "100%", marginTop: 14 }} onClick={setBaselineToCurrent}>
                Set baseline = current
              </button>
            </div>
          </div>

          {/* ADD TRADE */}
          <div style={{ ...s.panel, marginTop: 16 }}>
            <div style={s.panelHead}>
              <div style={s.panelTitleWrap}>
                <div style={s.panelIcon}>➕</div>
                <div>
                  <h3 style={s.panelTitle}>Add a Trade</h3>
                  <p style={s.panelSub}>Logged into the tamper-evident hash chain</p>
                </div>
              </div>
            </div>
            <div style={s.row}>
              <input
                style={s.field}
                type="number"
                placeholder="Profit (+) or loss (−), e.g. 500 or -300"
                value={profitLossInput}
                onChange={(e) => setProfitLossInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAddTrade()}
              />
              <input
                style={{ ...s.field, flex: "2 1 260px" }}
                type="text"
                placeholder="Note — why you took this trade (optional)"
                value={noteInput}
                onChange={(e) => setNoteInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAddTrade()}
              />
              <button style={s.btnPrimary} onClick={handleAddTrade}>Add Trade</button>
            </div>
          </div>

          {/* WORKSPACE: Monthly Progress + Recent Trades */}
          <div style={s.workspace}>
            <div style={s.panel}>
              <div style={s.panelHead}>
                <div style={s.panelTitleWrap}>
                  <div style={s.panelIcon}>📊</div>
                  <div>
                    <h3 style={s.panelTitle}>Monthly Progress</h3>
                    <p style={s.panelSub}>P&amp;L broken down by month</p>
                  </div>
                </div>
                <button style={s.btnGhostSmall} onClick={exportMonthlyCSV}>⬇ CSV</button>
              </div>

              <div style={{ overflowX: "auto" }}>
                <table style={s.table}>
                  <thead>
                    <tr>
                      <th style={s.th}>Month</th>
                      <th style={s.th}>Trades</th>
                      <th style={s.th}>Win%</th>
                      <th style={s.th}>P&amp;L (₹)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {monthly.length === 0 ? (
                      <tr><td style={{ ...s.td, color: C.textFaint }} colSpan={4}>No data yet</td></tr>
                    ) : (
                      monthly.map(function (m) {
                        return (
                          <tr key={m.month}>
                            <td style={s.td}>{m.month}</td>
                            <td style={{ ...s.td, ...NUM }}>{m.trades}</td>
                            <td style={{ ...s.td, ...NUM }}>{m.winPct}%</td>
                            <td style={{ ...s.td, ...NUM, color: m.pnl >= 0 ? C.green : C.red, fontWeight: 700 }}>
                              {(m.pnl >= 0 ? "+" : "-") + "₹" + fmtINR(Math.abs(m.pnl))}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              <div ref={monthChartWrapRef} style={s.chartWrap}>
                <canvas ref={monthCanvasRef} />
              </div>
            </div>

            <div style={s.panel}>
              <div style={s.panelHead}>
                <div style={s.panelTitleWrap}>
                  <div style={s.panelIcon}>📜</div>
                  <div>
                    <h3 style={s.panelTitle}>Recent Trades</h3>
                    <p style={s.panelSub}>{trades.length} total, newest first</p>
                  </div>
                </div>
              </div>

              {trades.length === 0 ? (
                <div style={{ color: C.textFaint, fontSize: 13, padding: "22px 0", textAlign: "center" }}>No trades yet</div>
              ) : (
                <div style={s.tradesScroll}>
                  {trades.map(function (t) {
                    return (
                      <div key={t.id} style={s.tradeItem}>
                        <div>
                          <div>
                            <strong style={{ fontSize: 13, fontWeight: 700, letterSpacing: "-0.01em" }}>{"Trade #" + t.id}</strong>
                            <span style={{ color: C.textFaint, fontSize: 12 }}> • {t.date}</span>
                            <span style={s.badge(t.profitLoss >= 0)}>
                              {t.profitLoss >= 0 ? "WIN" : "LOSS"}
                            </span>
                          </div>
                          {t.note ? <div style={s.note}>{t.note}</div> : null}
                          <div style={{ color: C.textFaint, fontSize: 10.5, marginTop: 4, fontFamily: "monospace" }}>
                            h:{t.hash ? t.hash.slice(-8) : ""} • prev:{t.prevHash ? t.prevHash.slice(-8) : ""}
                          </div>
                        </div>
                        <div style={t.profitLoss >= 0 ? s.green : s.red}>
                          {(t.profitLoss >= 0 ? "+" : "-") + "₹" + fmtINR(Math.abs(t.profitLoss))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* PER-TRADE BAR CHART */}
          <div style={{ ...s.panel, marginTop: 16 }}>
            <div style={s.panelHead}>
              <div style={s.panelTitleWrap}>
                <div style={s.panelIcon}>📈</div>
                <div>
                  <h3 style={s.panelTitle}>Trade P&amp;L — Bar Chart</h3>
                  <p style={s.panelSub}>Chronological, per trade</p>
                </div>
              </div>
            </div>
            <div ref={tradeChartWrapRef} style={s.chartWrap}>
              <canvas ref={tradeCanvasRef} />
            </div>
          </div>

        </div>
      </main>
    </div>
  );
}