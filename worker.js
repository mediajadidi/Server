// ============================================================
// 🔴 AJ SPORTS – Cloudflare Worker v9.0 (Broadcast Control Room)
// ------------------------------------------------------------
//  • ماشین وضعیت مسابقه سمت سرور (تنها منبع حقیقت برای همهٔ کاربران)
//  • پایگاه داده KV با کلید جدا برای هر مسابقه + نسخه‌گذاری (rev) ضد Overwrite
//  • API ادمین با توکن امضاشدهٔ HMAC (بدون رمز هاردکد)
//  • جستجوی مسابقه از apiv3.apifootball.com + پر شدن خودکار + پوستر SVG خودکار
//  • SSE وضعیت زنده (/api/state/events)
//  • پروکسی استریم با محافظ SSRF + Allowlist اختیاری
//
//  Secrets لازم:  ADMIN_SECRET , API_KEY_FOOTBALL
//  KV Binding:    MATCHES_STORE
//  Vars اختیاری:  ALLOWED_ORIGINS , PROXY_ALLOWED_HOSTS , DISPLAY_TZ
// ============================================================

export const VERSION = '9.0.0';

// ───────────────────────── ثابت‌ها ─────────────────────────
export const PHASES = [
  'scheduled', 'prematch', 'first_half', 'halftime', 'second_half',
  'extra_time', 'penalties', 'live', 'paused', 'finished', 'postmatch',
  'postponed', 'cancelled'
];
export const OPEN_PHASES = new Set([
  'prematch', 'first_half', 'halftime', 'second_half', 'extra_time', 'penalties', 'live', 'paused'
]);
const PLAYABLE_PHASES = new Set([...OPEN_PHASES, 'finished']);
const OVERRIDABLE = new Set([...PHASES, 'hidden']);

const POST_MS = 25 * 60 * 1000;          // مدت نمایش «پایان بازی» قبل از «پس از بازی»
const DEFAULT_PREMATCH_MIN = 30;         // باز شدن خودکار پیش‌بازی
const API_BASE = 'https://apiv3.apifootball.com/';
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

const FOOTBALL_ACTIONS = new Set([
  'get_events', 'get_statistics', 'get_lineups', 'get_teams', 'get_standings',
  'get_H2H', 'get_videos', 'get_leagues', 'get_countries', 'get_players',
  'get_topscorers', 'get_predictions', 'get_odds', 'get_live_odds_commnets'
]);
const FOOTBALL_PARAMS = new Set([
  'match_id', 'team_id', 'league_id', 'country_id', 'from', 'to', 'timezone',
  'match_live', 'withPlayerStats', 'player_id', 'player_name',
  'firstTeam', 'secondTeam', 'firstTeamId', 'secondTeamId'
]);

// ───────────────────────── ابزارها ─────────────────────────
const enc = new TextEncoder();

function json(data, status, cors, extra) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...(cors || {}), ...(extra || {}) }
  });
}
const err = (message, status, cors, extra) => json({ error: message, ...(extra || {}) }, status || 400, cors);

function corsFor(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  let allow = '*';
  if (allowed.length) allow = allowed.includes(origin) ? origin : allowed[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, admin-token, If-Match',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

const toInt = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : null; };
const str = (v, max) => (v == null ? '' : String(v)).trim().slice(0, max || 300);
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

export function escapeXml(s) {
  return String(s ?? '').replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));
}

async function sha256(text) { return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text))); }
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([sha256(String(a)), sha256(String(b))]);
  let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}
async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}

// ───────────────────── احراز هویت ادمین ─────────────────────
export async function issueToken(env, now) {
  const exp = (now || Date.now()) + TOKEN_TTL_MS;
  const sig = await hmacHex(env.ADMIN_SECRET, `v1.${exp}`);
  return { token: `v1.${exp}.${sig}`, expiresAt: exp };
}
async function verifyToken(env, token, now) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return false;
  const exp = Number(parts[1]);
  if (!Number.isFinite(exp) || exp < (now || Date.now())) return false;
  return safeEqual(await hmacHex(env.ADMIN_SECRET, `v1.${exp}`), parts[2]);
}
// خروجی: 'ok' | 'disabled' | 'denied'
async function authAdmin(request, env) {
  if (!env.ADMIN_SECRET || String(env.ADMIN_SECRET).length < 8) return 'disabled';
  const bearer = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const legacy = request.headers.get('admin-token') || '';
  const cand = bearer || legacy;
  if (!cand) return 'denied';
  if (cand.startsWith('v1.')) return (await verifyToken(env, cand)) ? 'ok' : 'denied';
  return (await safeEqual(cand, env.ADMIN_SECRET)) ? 'ok' : 'denied';
}

// محدودسازی نرخ (در سطح Isolate؛ برای حفاظت پایه کافی است)
const rateBuckets = new Map();
export function rateLimit(key, limit, windowMs, now) {
  const t = now || Date.now();
  let b = rateBuckets.get(key);
  if (!b || b.reset < t) { b = { n: 0, reset: t + windowMs }; rateBuckets.set(key, b); }
  b.n++;
  if (rateBuckets.size > 5000) for (const [k, v] of rateBuckets) if (v.reset < t) rateBuckets.delete(k);
  return b.n <= limit;
}
const clientIp = (r) => r.headers.get('CF-Connecting-IP') || r.headers.get('x-forwarded-for') || 'anon';

// ─────────────────── ماشین وضعیت مسابقه (هستهٔ سیستم) ───────────────────
/**
 * match_status در apiv3.apifootball.com (طبق مستندات رسمی):
 *  "13'" دقیقهٔ بازی | "Half Time" | "Finished" | "After ET" | "After Pen."
 *  "Postponed" | "Cancelled" | "Awarded"  و برای بازی شروع‌نشده رشتهٔ خالی.
 */
export function parseStatus(raw) {
  const s = String(raw ?? '').trim();
  if (s === '') return { kind: 'notstarted' };
  const low = s.toLowerCase();
  if (low === 'finished') return { kind: 'finished' };
  if (low === 'after et') return { kind: 'finished', et: true };
  if (low === 'after pen.' || low === 'after pen') return { kind: 'finished', pen: true };
  if (low === 'awarded') return { kind: 'finished', awarded: true };
  if (low === 'half time' || low === 'ht') return { kind: 'halftime' };
  if (low === 'postponed') return { kind: 'postponed' };
  if (low === 'cancelled' || low === 'canceled') return { kind: 'cancelled' };
  if (low === 'suspended' || low === 'interrupted' || low === 'abandoned') return { kind: 'suspended' };
  if (/^(not started|ns|tbd|scheduled)$/.test(low)) return { kind: 'notstarted' };
  const m = s.match(/^(\d{1,3})\s*(?:\+\s*(\d{1,2}))?\s*'?$/);
  if (m) return { kind: 'live', minute: +m[1], added: m[2] ? +m[2] : 0, label: s.replace(/'$/, '') };
  if (/pen/i.test(low)) return { kind: 'penalties' };
  return { kind: 'unknown', raw: s };
}

export function apiKickoffMs(api) {
  if (!api || !api.match_date || !api.match_time) return null;
  const t = Date.parse(`${api.match_date}T${api.match_time}:00Z`);
  return Number.isFinite(t) ? t : null;
}

/**
 * ورودی: رکورد ادمین (rec) + دادهٔ زندهٔ API (api یا null) + حالت قبلی (prev)
 * خروجی: { phase, source, minute?, finishedAt? }
 *  source: 'override' | 'api' | 'clock' | 'legacy'
 */
export function computePhase({ rec, api, now, prev }) {
  const t = now || Date.now();
  const prematchMs = (toInt(rec.prematchMin) ?? DEFAULT_PREMATCH_MIN) * 60000;

  // ۱) Override دستی ادمین همیشه برنده است
  if (rec.override && rec.override.phase && OVERRIDABLE.has(rec.override.phase)) {
    const ph = rec.override.phase;
    return { phase: ph, source: 'override', finishedAt: ph === 'finished' ? (prev?.finishedAt || t) : undefined };
  }

  const kickoff = rec.kickoff ? Date.parse(rec.kickoff) : apiKickoffMs(api);
  const kick = Number.isFinite(kickoff) ? kickoff : null;

  // ۲) دادهٔ واقعی API
  if (api && api.match_status !== undefined) {
    const st = parseStatus(api.match_status);
    switch (st.kind) {
      case 'live': {
        const base = st.minute;
        let phase = 'second_half';
        if (base <= 45) phase = 'first_half';
        else if (base > 90) phase = 'extra_time';
        return { phase, source: 'api', minute: st.label };
      }
      case 'halftime': return { phase: 'halftime', source: 'api', minute: 'HT' };
      case 'penalties': return { phase: 'penalties', source: 'api' };
      case 'suspended': return { phase: 'paused', source: 'api' };
      case 'postponed': return { phase: 'postponed', source: 'api' };
      case 'cancelled': return { phase: 'cancelled', source: 'api' };
      case 'finished': {
        const finishedAt = prev?.finishedAt || t;
        const longAgo = kick !== null && t - kick > 4 * 3600000;
        const post = longAgo || t - finishedAt > POST_MS;
        return { phase: post ? 'postmatch' : 'finished', source: 'api', finishedAt };
      }
      default: break; // notstarted / unknown → به منطق ساعت می‌رویم
    }
    if (kick !== null) {
      const diff = kick - t;
      if (diff > prematchMs) return { phase: 'scheduled', source: 'api' };
      // موعد بازی رسیده ولی API هنوز شروع نشان نمی‌دهد → پیش‌بازی (در انتظار)
      if (diff > -4 * 3600000) return { phase: 'prematch', source: 'api' };
      return { phase: 'postmatch', source: 'clock' };
    }
  }

  // ۳) بدون API: تخمین از روی ساعت (در صورت داشتن زمان شروع)
  if (kick !== null) {
    const diff = kick - t;
    if (diff > prematchMs) return { phase: 'scheduled', source: 'clock' };
    if (diff > 0) return { phase: 'prematch', source: 'clock' };
    const el = -diff / 60000;
    if (el <= 47) return { phase: 'first_half', source: 'clock', minute: String(Math.max(1, Math.floor(el))) };
    if (el <= 63) return { phase: 'halftime', source: 'clock', minute: 'HT' };
    if (el <= 112) return { phase: 'second_half', source: 'clock', minute: String(Math.min(90, Math.floor(el - 17))) };
    if (el <= 140) return { phase: 'finished', source: 'clock', finishedAt: prev?.finishedAt || t };
    return { phase: 'postmatch', source: 'clock' };
  }

  // ۴) سازگاری با وضعیت دستی قدیمی (پنل نسخهٔ ۳)
  switch (rec.status) {
    case 'live': return { phase: 'live', source: 'legacy' };
    case 'paused': return { phase: 'paused', source: 'legacy' };
    case 'finished': return { phase: 'finished', source: 'legacy', finishedAt: prev?.finishedAt || t };
    default: return { phase: 'scheduled', source: 'legacy' };
  }
}

export function legacyStatus(phase) {
  if (phase === 'paused') return 'paused';
  if (OPEN_PHASES.has(phase)) return 'live';
  if (phase === 'finished' || phase === 'postmatch') return 'finished';
  return 'upcoming';
}

// ───────────────────── دسترسی به KV ─────────────────────
const kvGet = (env, k) => env.MATCHES_STORE.get(k, { type: 'json' });
const kvPut = (env, k, v) => env.MATCHES_STORE.put(k, JSON.stringify(v));

async function listRecords(env) {
  await migrateLegacy(env);
  const ids = [];
  let cursor;
  do {
    const res = await env.MATCHES_STORE.list({ prefix: 'm:', cursor });
    (res.keys || []).forEach(k => ids.push(k.name));
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  const recs = await Promise.all(ids.map(k => kvGet(env, k).catch(() => null)));
  return recs.filter(Boolean);
}

// مهاجرت یک‌باره از کلید قدیمی live_matches (آرایه‌ای) به کلیدهای جداگانه
async function migrateLegacy(env) {
  try {
    if (await env.MATCHES_STORE.get('migrated_v9')) return;
    const old = await kvGet(env, 'live_matches');
    if (Array.isArray(old)) {
      for (const m of old) {
        const rec = normalizeRecord(m, null);
        if (rec.error) continue;
        await kvPut(env, `m:${rec.value.id}`, rec.value);
      }
    }
    await env.MATCHES_STORE.put('migrated_v9', '1');
  } catch (e) { console.error('migrate failed', e && e.message); }
}

async function audit(env, entry) {
  try {
    const list = (await kvGet(env, 'audit')) || [];
    list.unshift({ ts: Date.now(), ...entry });
    await kvPut(env, 'audit', list.slice(0, 200));
  } catch { /* ثبت لاگ نباید عملیات اصلی را خراب کند */ }
}

// ─────────────────── اعتبارسنجی و نرمال‌سازی رکورد ───────────────────
const ID_RE = /^[A-Za-z0-9_-]{3,64}$/;
export function isHttpUrl(u) {
  try { const x = new URL(u); return x.protocol === 'https:' || x.protocol === 'http:'; } catch { return false; }
}
function cleanTeam(t) {
  if (!t || typeof t !== 'object') return null;
  const name = str(t.name, 80); const logo = isHttpUrl(t.logo) ? String(t.logo).slice(0, 500) : '';
  const id = str(t.id, 20);
  return name || logo ? { id, name, logo } : null;
}

export function normalizeRecord(input, existing) {
  const src = input && typeof input === 'object' ? input : {};
  const base = existing ? { ...existing } : {};
  const id = base.id || str(src.id, 64) || `m_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  if (!ID_RE.test(id)) return { error: 'شناسهٔ مسابقه نامعتبر است' };

  const title = 'title' in src ? str(src.title, 160) : (base.title || '');
  if (!title) return { error: 'عنوان مسابقه الزامی است' };

  let kickoff = 'kickoff' in src ? src.kickoff : base.kickoff;
  if (kickoff) {
    const t = Date.parse(kickoff);
    if (!Number.isFinite(t)) return { error: 'زمان شروع نامعتبر است' };
    kickoff = new Date(t).toISOString();
  } else kickoff = null;

  const srcSources = 'sources' in src ? src.sources : base.sources;
  let sources = [];
  if (Array.isArray(srcSources)) {
    for (const s of srcSources.slice(0, 6)) {
      const url = str(s && s.url, 1000);
      if (!url) continue;
      if (!isHttpUrl(url)) return { error: `لینک پخش نامعتبر: ${url.slice(0, 60)}` };
      sources.push({ id: str(s.id, 24) || `s${sources.length + 1}`, label: str(s.label, 40) || `منبع ${sources.length + 1}`, url });
    }
  }
  // سازگاری عقب‌رو: فیلد قدیمی stream → منبع اول
  const legacyStream = 'stream' in src ? str(src.stream, 1000) : '';
  if (!sources.length && legacyStream) {
    if (!isHttpUrl(legacyStream)) return { error: 'لینک پخش نامعتبر است' };
    sources = [{ id: 's1', label: 'منبع ۱', url: legacyStream }];
  }
  if (!sources.length && base.stream && !('sources' in src)) sources = [{ id: 's1', label: 'منبع ۱', url: base.stream }];

  const poster = 'poster' in src ? str(src.poster, 600) : (base.poster || '');
  if (poster && !isHttpUrl(poster)) return { error: 'لینک پوستر نامعتبر است' };

  const matchId = 'match_id' in src ? str(src.match_id, 20) : (base.match_id || '');
  if (matchId && !/^\d{1,12}$/.test(matchId)) return { error: 'شناسهٔ API فقط عدد است' };

  const status = 'status' in src ? str(src.status, 12) : (base.status || 'upcoming');

  const rec = {
    ...base,
    id, title, kickoff,
    time: 'time' in src ? str(src.time, 20) : (base.time || ''),
    poster,
    sources,
    stream: sources[0] ? sources[0].url : '',
    match_id: matchId || null,
    status: ['live', 'upcoming', 'finished', 'paused'].includes(status) ? status : 'upcoming',
    prematchMin: 'prematchMin' in src ? Math.min(240, Math.max(0, toInt(src.prematchMin) ?? DEFAULT_PREMATCH_MIN)) : (base.prematchMin ?? DEFAULT_PREMATCH_MIN),
    visible: 'visible' in src ? !!src.visible : (base.visible !== false),
    pinned: 'pinned' in src ? !!src.pinned : !!base.pinned,
    order: 'order' in src ? (toInt(src.order) ?? 0) : (base.order ?? 0),
    home: 'home' in src ? cleanTeam(src.home) : (base.home || null),
    away: 'away' in src ? cleanTeam(src.away) : (base.away || null),
    league: 'league' in src ? (src.league && typeof src.league === 'object'
      ? { id: str(src.league.id, 12), name: str(src.league.name, 100), logo: isHttpUrl(src.league.logo) ? String(src.league.logo).slice(0, 500) : '', country: str(src.league.country, 60), round: str(src.league.round, 40) }
      : null) : (base.league || null),
    override: base.override || null,
    createdAt: base.createdAt || Date.now()
  };
  return { value: rec };
}

// ─────────────────── دریافت از apiv3.apifootball.com ───────────────────
async function fetchApi(env, ctx, action, params, ttl) {
  if (!env.API_KEY_FOOTBALL) return { ok: false, data: null, reason: 'no_key' };
  const sp = new URLSearchParams();
  Object.keys(params).sort().forEach(k => { if (params[k] !== undefined && params[k] !== '') sp.set(k, params[k]); });
  const keyUrl = `https://fb-cache.internal/${action}?${sp.toString()}`;
  const cache = caches.default;
  const cacheReq = new Request(keyUrl);
  const hit = await cache.match(cacheReq);
  if (hit) { try { return { ok: true, data: await hit.json(), cached: true }; } catch { /* ادامه */ } }

  const u = new URL(API_BASE);
  u.searchParams.set('action', action);
  sp.forEach((v, k) => u.searchParams.set(k, v));
  u.searchParams.set('APIkey', env.API_KEY_FOOTBALL);
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 8000);
    const res = await fetch(u.toString(), { signal: ctl.signal });
    clearTimeout(timer);
    const data = await res.json();
    // apifootball در خطا/نتیجهٔ خالی یک آبجکت {error:404,message:..} برمی‌گرداند
    const failed = !res.ok || (data && !Array.isArray(data) && data.error !== undefined && action !== 'get_lineups' && action !== 'get_statistics');
    const store = new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json', 'Cache-Control': `public, s-maxage=${failed ? 5 : ttl}` } });
    const p = cache.put(cacheReq, store);
    if (ctx && ctx.waitUntil) ctx.waitUntil(p); else await p;
    return { ok: !failed, data };
  } catch (e) {
    return { ok: false, data: null, reason: e && e.name === 'AbortError' ? 'timeout' : 'network' };
  }
}

async function getApiMatch(env, ctx, matchId, prevPhase) {
  if (!matchId) return null;
  const open = prevPhase && OPEN_PHASES.has(prevPhase);
  const ttl = open ? 8 : (prevPhase === 'finished' || prevPhase === 'postmatch' ? 300 : 60);
  const r = await fetchApi(env, ctx, 'get_events', { match_id: matchId, timezone: 'UTC' }, ttl);
  if (!r.ok || !Array.isArray(r.data) || !r.data[0]) return null;
  return r.data[0];
}

// ─────────────────── ساخت خروجی عمومی ───────────────────
const DISPLAY_TZ_DEFAULT = 'Asia/Tehran';
function fmtTime(ms, tz) {
  try { return new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: tz || DISPLAY_TZ_DEFAULT }).format(new Date(ms)); }
  catch { return ''; }
}

export function buildEntry({ rec, api, prev, now, origin, tz }) {
  const comp = computePhase({ rec, api, now, prev });
  const kMs = rec.kickoff ? Date.parse(rec.kickoff) : apiKickoffMs(api);
  const started = api && parseStatus(api.match_status).kind !== 'notstarted';
  const home = { id: api?.match_hometeam_id || rec.home?.id || '', name: api?.match_hometeam_name || rec.home?.name || '', logo: api?.team_home_badge || rec.home?.logo || '' };
  const away = { id: api?.match_awayteam_id || rec.away?.id || '', name: api?.match_awayteam_name || rec.away?.name || '', logo: api?.team_away_badge || rec.away?.logo || '' };
  const league = {
    id: api?.league_id || rec.league?.id || '', name: api?.league_name || rec.league?.name || '',
    logo: api?.league_logo || rec.league?.logo || '', country: api?.country_name || rec.league?.country || '',
    round: api?.match_round || rec.league?.round || ''
  };
  const sources = (rec.sources || []).map(s => ({ id: s.id, label: s.label, url: s.url }));
  return {
    id: rec.id,
    title: rec.title,
    kickoff: kMs ? new Date(kMs).toISOString() : null,
    time: kMs ? fmtTime(kMs, tz) : (rec.time || ''),
    poster: rec.poster || `${origin}/api/poster/${rec.id}.svg`,
    stream: sources[0] ? sources[0].url : '',
    sources,
    match_id: rec.match_id || null,
    status: legacyStatus(comp.phase),
    phase: comp.phase,
    phaseSource: comp.source,
    live: OPEN_PHASES.has(comp.phase) && comp.phase !== 'prematch' && comp.phase !== 'paused',
    playable: PLAYABLE_PHASES.has(comp.phase),
    minute: comp.minute || null,
    score: api && started ? { home: toInt(api.match_hometeam_score) ?? 0, away: toInt(api.match_awayteam_score) ?? 0 } : null,
    htScore: api && api.match_hometeam_halftime_score !== '' && api.match_hometeam_halftime_score != null
      ? { home: toInt(api.match_hometeam_halftime_score), away: toInt(api.match_awayteam_halftime_score) } : null,
    home, away, league,
    stadium: api?.match_stadium || '',
    referee: api?.match_referee || '',
    pinned: !!rec.pinned,
    order: rec.order || 0,
    visible: rec.visible !== false,
    override: rec.override || null,
    prematchMin: rec.prematchMin ?? DEFAULT_PREMATCH_MIN,
    rev: rec.rev || 0,
    updatedAt: rec.updatedAt || 0,
    _finishedAt: comp.finishedAt,
    _since: prev && prev.phase === comp.phase ? prev.since : undefined
  };
}

const PHASE_RANK = { live: 0, first_half: 0, second_half: 0, extra_time: 0, penalties: 0, halftime: 1, paused: 1, prematch: 2, scheduled: 3, finished: 4, postmatch: 5, postponed: 6, cancelled: 7 };
export function sortEntries(list) {
  return list.sort((a, b) =>
    (b.pinned - a.pinned) ||
    ((PHASE_RANK[a.phase] ?? 9) - (PHASE_RANK[b.phase] ?? 9)) ||
    (a.order - b.order) ||
    ((Date.parse(a.kickoff) || 0) - (Date.parse(b.kickoff) || 0))
  );
}

async function buildAll(env, ctx, origin, { includeHidden } = {}) {
  const recs = await listRecords(env);
  const now = Date.now();
  const states = await Promise.all(recs.map(r => kvGet(env, `s:${r.id}`).catch(() => null)));
  const apis = await Promise.all(recs.map((r, i) => getApiMatch(env, ctx, r.match_id, states[i]?.phase)));
  const tz = env.DISPLAY_TZ || DISPLAY_TZ_DEFAULT;
  const entries = [];
  const writes = [];
  recs.forEach((rec, i) => {
    const e = buildEntry({ rec, api: apis[i], prev: states[i], now, origin, tz });
    // ثبت گذار وضعیت (فقط هنگام تغییر؛ تا KV Write هرز نزنیم)
    if (!states[i] || states[i].phase !== e.phase || (e._finishedAt && !states[i].finishedAt)) {
      writes.push(kvPut(env, `s:${rec.id}`, { phase: e.phase, since: now, finishedAt: e._finishedAt || states[i]?.finishedAt || null, source: e.phaseSource }));
    }
    delete e._finishedAt; delete e._since;
    if (e.visible || includeHidden) entries.push(e);
  });
  if (writes.length) { const p = Promise.allSettled(writes); if (ctx && ctx.waitUntil) ctx.waitUntil(p); else await p; }
  return sortEntries(entries);
}

// حافظهٔ ۳ ثانیه‌ای در Isolate: جلوگیری از فشار روی KV وقتی هزاران کاربر هم‌زمان می‌خوانند
let memo = { at: 0, key: '', data: null, pending: null };
async function publicList(env, ctx, origin) {
  const t = Date.now();
  if (memo.data && memo.key === origin && t - memo.at < 3000) return memo.data;
  if (memo.pending && memo.key === origin) return memo.pending;
  memo.key = origin;
  memo.pending = buildAll(env, ctx, origin).then(d => { memo = { at: Date.now(), key: origin, data: d, pending: null }; return d; })
    .catch(e => { memo.pending = null; throw e; });
  return memo.pending;
}
export function invalidateMemo() { memo = { at: 0, key: '', data: null, pending: null }; }

// ─────────────────── SSRF و پروکسی استریم ───────────────────
export function isSafeRemoteUrl(u, allowedHosts) {
  let x; try { x = new URL(u); } catch { return false; }
  if (x.protocol !== 'http:' && x.protocol !== 'https:') return false;
  const h = x.hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.localhost')) return false;
  if (h.startsWith('[') || h.includes(':')) return false;                       // IPv6 literal
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b] = [+m[1], +m[2]];
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
  }
  if (allowedHosts && allowedHosts.length) return allowedHosts.some(a => h === a || h.endsWith('.' + a));
  return true;
}
const parseAllowed = (env) => String(env.PROXY_ALLOWED_HOSTS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// ─────────────────── پوستر SVG خودکار ───────────────────
async function toDataUri(url) {
  if (!url || !isHttpUrl(url)) return '';
  try {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 4000);
    const res = await fetch(url, { signal: ctl.signal }); clearTimeout(t);
    if (!res.ok) return '';
    const buf = await res.arrayBuffer();
    if (buf.byteLength > 400000) return '';
    const ct = (res.headers.get('content-type') || 'image/png').split(';')[0];
    let bin = ''; const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return `data:${ct};base64,${btoa(bin)}`;
  } catch { return ''; }
}
export function posterSvg({ home, away, league, timeLabel, dateLabel, homeImg, awayImg, leagueImg }) {
  const initials = (n) => escapeXml((n || '?').split(/\s+/).map(w => w[0]).join('').slice(0, 3).toUpperCase());
  const logo = (img, cx, name) => img
    ? `<circle cx="${cx}" cy="330" r="118" fill="#ffffff10" stroke="#ffffff30" stroke-width="2"/><image href="${img}" x="${cx - 78}" y="252" width="156" height="156" preserveAspectRatio="xMidYMid meet"/>`
    : `<circle cx="${cx}" cy="330" r="118" fill="#ffffff12" stroke="#ffffff30" stroke-width="2"/><text x="${cx}" y="350" font-size="64" font-weight="800" fill="#fff" text-anchor="middle" font-family="Helvetica,Arial,sans-serif">${initials(name)}</text>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 720" width="1280" height="720">
<defs>
<radialGradient id="bg" cx="50%" cy="38%" r="80%"><stop offset="0" stop-color="#1a1d33"/><stop offset="1" stop-color="#05060b"/></radialGradient>
<linearGradient id="bar" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#ff1744"/><stop offset="1" stop-color="#ff6d00"/></linearGradient>
<filter id="glow"><feGaussianBlur stdDeviation="22"/></filter>
</defs>
<rect width="1280" height="720" fill="url(#bg)"/>
<circle cx="320" cy="330" r="190" fill="#ff1744" opacity=".16" filter="url(#glow)"/>
<circle cx="960" cy="330" r="190" fill="#2979ff" opacity=".18" filter="url(#glow)"/>
<g opacity=".05" stroke="#fff"><path d="M0 120H1280M0 240H1280M0 360H1280M0 480H1280M0 600H1280"/></g>
${leagueImg ? `<image href="${leagueImg}" x="590" y="44" width="100" height="100" preserveAspectRatio="xMidYMid meet"/>` : ''}
<text x="640" y="${leagueImg ? 176 : 100}" font-size="30" font-weight="700" fill="#ffffffcc" text-anchor="middle" font-family="Helvetica,Arial,sans-serif">${escapeXml(league || '')}</text>
${logo(homeImg, 320, home)}${logo(awayImg, 960, away)}
<text x="640" y="342" font-size="64" font-weight="900" font-style="italic" fill="#ffd54a" text-anchor="middle" font-family="Helvetica,Arial,sans-serif">VS</text>
<text x="640" y="400" font-size="40" font-weight="800" fill="#fff" text-anchor="middle" font-family="Helvetica,Arial,sans-serif">${escapeXml(timeLabel || '')}</text>
<text x="320" y="522" font-size="38" font-weight="800" fill="#fff" text-anchor="middle" font-family="Helvetica,Arial,sans-serif">${escapeXml((home || '').slice(0, 22))}</text>
<text x="960" y="522" font-size="38" font-weight="800" fill="#fff" text-anchor="middle" font-family="Helvetica,Arial,sans-serif">${escapeXml((away || '').slice(0, 22))}</text>
<text x="640" y="450" font-size="24" fill="#ffffff90" text-anchor="middle" font-family="Helvetica,Arial,sans-serif">${escapeXml(dateLabel || '')}</text>
<rect x="0" y="650" width="1280" height="70" fill="#00000080"/><rect x="0" y="646" width="1280" height="4" fill="url(#bar)"/>
<text x="640" y="697" font-size="30" font-weight="900" letter-spacing="6" fill="#fff" text-anchor="middle" font-family="Helvetica,Arial,sans-serif">AJ SPORTS</text>
</svg>`;
}

// ─────────────────── مسیریابی اصلی ───────────────────
async function readBody(request, max) {
  const text = await request.text();
  if (text.length > (max || 200000)) throw new Error('payload_too_large');
  return text ? JSON.parse(text) : {};
}

async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = request.method;
  const cors = corsFor(request, env);
  const origin = url.origin;

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  // ── ریشه ──
  if ((path === '/' || path === '/api') && method === 'GET') {
    return json({
      status: `🚀 AJ SPORTS API v${VERSION}`,
      endpoints: ['/api/matches', '/api/state', '/api/state/events', '/api/poster/:id.svg', '/api/football/:action', '/api/chat', '/api/chat/events', '/api/stream-proxy', '/api/admin/*']
    }, 200, cors);
  }

  // ── لیست عمومی ──
  if (path === '/api/matches' && method === 'GET') {
    const data = await publicList(env, ctx, origin);
    return json(data, 200, cors, { 'Cache-Control': 'public, max-age=0, s-maxage=3, stale-while-revalidate=5' });
  }

  // ── وضعیت یک مسابقه ──
  if (path === '/api/state' && method === 'GET') {
    const id = url.searchParams.get('id');
    const mid = url.searchParams.get('match_id');
    const list = await publicList(env, ctx, origin);
    const found = list.find(e => (id && e.id === id) || (mid && e.match_id === mid));
    if (!found) return err('not_found', 404, cors);
    return json(found, 200, cors, { 'Cache-Control': 'public, max-age=0, s-maxage=3' });
  }

  // ── SSE وضعیت زنده ──
  if (path === '/api/state/events' && method === 'GET') {
    const encoder = new TextEncoder();
    let timers = [];
    const stream = new ReadableStream({
      async start(controller) {
        const send = (event, data) => { try { controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)); } catch { /* بسته شده */ } };
        const sig = (e) => `${e.phase}|${e.minute}|${e.score ? e.score.home + '-' + e.score.away : ''}|${e.rev}|${e.override ? e.override.phase : ''}|${e.sources.map(s => s.url).join(',')}`;
        let known = new Map();
        const tick = async (first) => {
          try {
            const list = await publicList(env, ctx, origin);
            if (first) { send('snapshot', list); list.forEach(e => known.set(e.id, sig(e))); return; }
            const seen = new Set();
            for (const e of list) {
              seen.add(e.id);
              const s = sig(e);
              if (known.get(e.id) !== s) { known.set(e.id, s); send('change', e); }
            }
            for (const id of [...known.keys()]) if (!seen.has(id)) { known.delete(id); send('removed', { id }); }
          } catch { /* خطای لحظه‌ای، تیک بعدی */ }
        };
        controller.enqueue(encoder.encode('retry: 3000\n\n'));
        await tick(true);
        timers.push(setInterval(() => tick(false), 4000));
        timers.push(setInterval(() => { try { controller.enqueue(encoder.encode(`: hb ${Date.now()}\n\n`)); } catch { /* */ } }, 15000));
        // سقف عمر اتصال ۱۰ دقیقه؛ EventSource خودکار وصل می‌شود و Snapshot تازه می‌گیرد
        timers.push(setTimeout(() => { timers.forEach(clearInterval); try { controller.close(); } catch { /* */ } }, 600000));
        request.signal.addEventListener('abort', () => { timers.forEach(clearInterval); clearTimeout(timers[2]); });
      },
      cancel() { timers.forEach(clearInterval); }
    });
    return new Response(stream, {
      headers: { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', 'X-Accel-Buffering': 'no', ...cors }
    });
  }

  // ── پوستر SVG ──
  const posterM = path.match(/^\/api\/poster\/([A-Za-z0-9_-]{3,64})\.svg$/);
  if (posterM && method === 'GET') {
    const id = posterM[1];
    const cacheReq = new Request(`https://poster.internal/${id}`);
    const hit = await caches.default.match(cacheReq);
    if (hit) return new Response(hit.body, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=300', ...cors } });
    const rec = await kvGet(env, `m:${id}`);
    if (!rec) return err('not_found', 404, cors);
    const api = await getApiMatch(env, ctx, rec.match_id, null);
    const e = buildEntry({ rec, api, prev: null, now: Date.now(), origin, tz: env.DISPLAY_TZ || DISPLAY_TZ_DEFAULT });
    const [homeImg, awayImg, leagueImg] = await Promise.all([toDataUri(e.home.logo), toDataUri(e.away.logo), toDataUri(e.league.logo)]);
    const k = e.kickoff ? Date.parse(e.kickoff) : null;
    let dateLabel = '';
    if (k) { try { dateLabel = new Intl.DateTimeFormat('en-GB', { weekday: 'long', day: '2-digit', month: 'short', timeZone: env.DISPLAY_TZ || DISPLAY_TZ_DEFAULT }).format(new Date(k)); } catch { /* */ } }
    const svg = posterSvg({
      home: e.home.name || e.title, away: e.away.name || '', league: e.league.name,
      timeLabel: e.time, dateLabel, homeImg, awayImg, leagueImg
    });
    const res = new Response(svg, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=300', ...cors } });
    const p = caches.default.put(cacheReq, new Response(svg, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, s-maxage=900' } }));
    if (ctx && ctx.waitUntil) ctx.waitUntil(p);
    return res;
  }

  // ── پروکسی API فوتبال (Allowlist اکشن و پارامتر؛ کلید هرگز از کلاینت پذیرفته نمی‌شود) ──
  if (path.startsWith('/api/football/') && method === 'GET') {
    const action = path.slice('/api/football/'.length);
    if (!FOOTBALL_ACTIONS.has(action)) return err('action_not_allowed', 403, cors);
    if (!env.API_KEY_FOOTBALL) return err('API_KEY_FOOTBALL not set', 500, cors);
    if (!rateLimit(`fb:${clientIp(request)}`, 240, 60000)) return err('rate_limited', 429, cors);
    const params = {};
    for (const [k, v] of url.searchParams) if (FOOTBALL_PARAMS.has(k)) params[k] = String(v).slice(0, 80);
    if (action === 'get_events' && !params.timezone) params.timezone = 'UTC';
    const live = action === 'get_events' && (params.match_live || params.match_id);
    const ttl = live ? 8 : (action === 'get_statistics' || action === 'get_lineups' ? 15 : 60);
    const r = await fetchApi(env, ctx, action, params, ttl);
    if (r.data === null) return err('Football API unavailable', 502, cors);
    return json(r.data, 200, cors, { 'Cache-Control': `public, s-maxage=${ttl}, stale-while-revalidate=${ttl * 2}` });
  }

  // ── پروکسی استریم ──
  if (path === '/api/stream-proxy' && method === 'GET') {
    const target = url.searchParams.get('url');
    if (!target) return err('Missing url param', 400, cors);
    if (!isSafeRemoteUrl(target, parseAllowed(env))) return err('target_not_allowed', 403, cors);
    if (!rateLimit(`sp:${clientIp(request)}`, 600, 60000)) return err('rate_limited', 429, cors);
    try {
      let referer = url.searchParams.get('referer');
      if (!referer || !isHttpUrl(referer)) { const p = new URL(target); referer = `${p.protocol}//${p.host}/`; }
      const upstream = await fetch(target, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
          'Accept': '*/*', 'Origin': referer.replace(/\/$/, ''), 'Referer': referer,
          ...(request.headers.get('Range') ? { Range: request.headers.get('Range') } : {})
        },
        redirect: 'follow'
      });
      if (!upstream.ok && upstream.status !== 206) return err('Upstream error', 502, cors, { status: upstream.status });
      const h = new Headers(cors);
      h.set('Content-Type', upstream.headers.get('content-type') || 'application/vnd.apple.mpegurl');
      h.set('Cache-Control', 'public, max-age=3');
      return new Response(upstream.body, { status: upstream.status === 206 ? 206 : 200, headers: h });
    } catch (e) { return err('Proxy failed', 502, cors); }
  }

  // ── چت (نسخهٔ KV) ──
  if (path === '/api/chat' && method === 'GET') {
    const matchId = (url.searchParams.get('match_id') || 'global').slice(0, 64);
    const raw = await kvGet(env, `chat_${matchId}`).catch(() => null);
    return json({ messages: Array.isArray(raw) ? raw : [] }, 200, cors);
  }
  if (path === '/api/chat' && method === 'POST') {
    try {
      if (!rateLimit(`chat:${clientIp(request)}`, 20, 60000)) return err('rate_limited', 429, cors);
      const body = await readBody(request, 10000);
      const { text, email, avatar, reply_text, match_id } = body;
      if (!text || !email || !String(email).includes('@')) return err('Missing fields', 400, cors);
      const mid = str(match_id || 'global', 64);
      const message = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        text: str(text, 500), sender: String(email).split('@')[0].slice(0, 40), sender_identity_id: String(email).slice(0, 120),
        avatar: isHttpUrl(avatar) ? String(avatar).slice(0, 500) : '', reply_text: reply_text ? str(reply_text, 300) : null,
        match_id: mid, timestamp: Date.now()
      };
      const key = `chat_${mid}`;
      const cur = await kvGet(env, key).catch(() => null);
      const messages = [message, ...(Array.isArray(cur) ? cur : [])].slice(0, 100);
      await kvPut(env, key, messages);
      return json({ success: true, message }, 200, cors);
    } catch { return err('Invalid JSON', 400, cors); }
  }
  if (path === '/api/chat/events' && method === 'GET') {
    const matchId = (url.searchParams.get('match_id') || 'global').slice(0, 64);
    const encoder = new TextEncoder();
    let timers = [];
    const stream = new ReadableStream({
      async start(controller) {
        let lastCheck = Date.now();
        const check = async () => {
          try {
            const raw = await kvGet(env, `chat_${matchId}`);
            if (Array.isArray(raw)) {
              raw.filter(m => m.timestamp > lastCheck).reverse().forEach(msg =>
                controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'message', payload: msg })}\n\n`)));
              lastCheck = Date.now();
            }
          } catch { /* */ }
        };
        controller.enqueue(encoder.encode('retry: 3000\n\n'));
        timers.push(setInterval(() => { try { controller.enqueue(encoder.encode(`: hb\n\n`)); } catch { /* */ } }, 20000));
        timers.push(setInterval(check, 2500));
        timers.push(setTimeout(() => { timers.forEach(clearInterval); try { controller.close(); } catch { /* */ } }, 600000));
        request.signal.addEventListener('abort', () => timers.forEach(clearInterval));
      },
      cancel() { timers.forEach(clearInterval); }
    });
    return new Response(stream, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...cors } });
  }

  // ════════════════ مسیرهای ادمین ════════════════
  const isAdminPath = path.startsWith('/api/admin') || (path === '/api/matches' && method === 'POST');
  if (isAdminPath) {
    // ورود: تبدیل رمز به توکن ۱۲ ساعته
    if (path === '/api/admin/login' && method === 'POST') {
      if (!env.ADMIN_SECRET || String(env.ADMIN_SECRET).length < 8) return err('admin_disabled: ADMIN_SECRET تنظیم نشده یا کوتاه است', 503, cors);
      if (!rateLimit(`login:${clientIp(request)}`, 8, 10 * 60000)) return err('too_many_attempts', 429, cors);
      let body; try { body = await readBody(request, 2000); } catch { return err('Invalid JSON', 400, cors); }
      if (!(await safeEqual(body.secret || '', env.ADMIN_SECRET))) return err('invalid_credentials', 401, cors);
      return json({ success: true, ...(await issueToken(env)) }, 200, cors);
    }

    const auth = await authAdmin(request, env);
    if (auth === 'disabled') return err('admin_disabled: ADMIN_SECRET تنظیم نشده یا کوتاه است', 503, cors);
    if (auth !== 'ok') return err('Unauthorized', 401, cors);

    if (path === '/api/admin/ping' && method === 'GET') return json({ ok: true, version: VERSION, hasApiKey: !!env.API_KEY_FOOTBALL, now: Date.now() }, 200, cors);

    if (path === '/api/admin/matches' && method === 'GET') {
      invalidateMemo();
      return json(await buildAll(env, ctx, origin, { includeHidden: true }), 200, cors);
    }

    // ایجاد/ویرایش
    if (path === '/api/admin/match' && (method === 'POST' || method === 'PUT')) {
      let body; try { body = await readBody(request, 50000); } catch { return err('Invalid JSON', 400, cors); }
      const input = body.match || body;
      const existing = input.id ? await kvGet(env, `m:${input.id}`).catch(() => null) : null;
      const ifMatch = request.headers.get('If-Match') ?? (body.rev !== undefined ? String(body.rev) : null);
      if (existing && ifMatch !== null && String(existing.rev || 0) !== String(ifMatch)) {
        return err('conflict', 409, cors, { current: existing });
      }
      const norm = normalizeRecord(input, existing);
      if (norm.error) return err(norm.error, 422, cors);
      const rec = norm.value;
      rec.rev = (existing?.rev || 0) + 1;
      rec.updatedAt = Date.now();
      await kvPut(env, `m:${rec.id}`, rec);
      invalidateMemo();
      await audit(env, { action: existing ? 'update' : 'create', id: rec.id, title: rec.title });
      return json({ success: true, match: rec }, existing ? 200 : 201, cors);
    }

    const delM = path.match(/^\/api\/admin\/match\/([A-Za-z0-9_-]{3,64})$/);
    if (delM && method === 'DELETE') {
      const rec = await kvGet(env, `m:${delM[1]}`).catch(() => null);
      if (!rec) return err('not_found', 404, cors);
      await Promise.all([env.MATCHES_STORE.delete(`m:${delM[1]}`), env.MATCHES_STORE.delete(`s:${delM[1]}`)]);
      invalidateMemo();
      await audit(env, { action: 'delete', id: rec.id, title: rec.title });
      return json({ success: true }, 200, cors);
    }

    // Override فاز دستی (یا بازگشت به خودکار با phase=null)
    const ovM = path.match(/^\/api\/admin\/match\/([A-Za-z0-9_-]{3,64})\/override$/);
    if (ovM && method === 'POST') {
      const rec = await kvGet(env, `m:${ovM[1]}`).catch(() => null);
      if (!rec) return err('not_found', 404, cors);
      let body; try { body = await readBody(request, 2000); } catch { return err('Invalid JSON', 400, cors); }
      const ph = body.phase;
      if (ph === null || ph === undefined || ph === 'auto') rec.override = null;
      else if (OVERRIDABLE.has(ph)) {
        rec.override = { phase: ph, at: Date.now() };
        if (ph === 'hidden') rec.visible = false;
        else if (rec.visible === false && body.show !== false) rec.visible = true;
      } else return err('invalid_phase', 422, cors);
      rec.rev = (rec.rev || 0) + 1; rec.updatedAt = Date.now();
      await kvPut(env, `m:${rec.id}`, rec);
      await env.MATCHES_STORE.delete(`s:${rec.id}`);   // وضعیت زمان‌دار از نو محاسبه شود
      invalidateMemo();
      await audit(env, { action: 'override', id: rec.id, title: rec.title, phase: ph ?? 'auto' });
      return json({ success: true, match: rec }, 200, cors);
    }

    // جستجوی مسابقه از API
    if (path === '/api/admin/search' && method === 'GET') {
      if (!env.API_KEY_FOOTBALL) return err('API_KEY_FOOTBALL not set', 500, cors);
      const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
      const to = url.searchParams.get('to') || date;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{4}-\d{2}-\d{2}$/.test(to)) return err('invalid_date', 422, cors);
      const q = (url.searchParams.get('q') || '').trim().toLowerCase();
      const leagueId = url.searchParams.get('league_id') || '';
      const r = await fetchApi(env, ctx, 'get_events', { from: date, to, timezone: 'UTC', league_id: leagueId }, 60);
      if (r.data === null) return err('Football API unavailable', 502, cors);
      const arr = Array.isArray(r.data) ? r.data : [];
      const recs = await listRecords(env);
      const used = new Map(recs.filter(x => x.match_id).map(x => [String(x.match_id), x.id]));
      const items = arr.filter(m => !q || [m.match_hometeam_name, m.match_awayteam_name, m.league_name, m.country_name].some(v => String(v || '').toLowerCase().includes(q)))
        .slice(0, 80).map(m => ({
          match_id: String(m.match_id), kickoff: m.match_date && m.match_time ? `${m.match_date}T${m.match_time}:00.000Z` : null,
          status: m.match_status, score: m.match_hometeam_score !== '' ? `${m.match_hometeam_score}-${m.match_awayteam_score}` : '',
          home: { id: m.match_hometeam_id, name: m.match_hometeam_name, logo: m.team_home_badge },
          away: { id: m.match_awayteam_id, name: m.match_awayteam_name, logo: m.team_away_badge },
          league: { id: m.league_id, name: m.league_name, logo: m.league_logo, country: m.country_name, round: m.match_round },
          stadium: m.match_stadium || '', usedBy: used.get(String(m.match_id)) || null
        }));
      return json({ count: items.length, total: arr.length, items }, 200, cors);
    }

    // تست سلامت لینک پخش
    if (path === '/api/admin/check-source' && method === 'POST') {
      let body; try { body = await readBody(request, 3000); } catch { return err('Invalid JSON', 400, cors); }
      const target = String(body.url || '');
      if (!isSafeRemoteUrl(target, null)) return json({ ok: false, error: 'آدرس مجاز نیست (محلی/خصوصی/نامعتبر)' }, 200, cors);
      const t0 = Date.now();
      try {
        const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), 7000);
        const pu = new URL(target); const ref = `${pu.protocol}//${pu.host}/`;
        const res = await fetch(target, { signal: ctl.signal, headers: { 'User-Agent': 'Mozilla/5.0 AJSportsHealth/1.0', 'Referer': ref, 'Origin': ref.replace(/\/$/, ''), Range: 'bytes=0-4095' } });
        clearTimeout(timer);
        const ct = res.headers.get('content-type') || '';
        let kind = 'unknown', variants = 0;
        const looksM3u8 = /mpegurl/i.test(ct) || /\.m3u8(\?|$)/i.test(target);
        if (looksM3u8) {
          const text = (await res.text()).slice(0, 8000);
          kind = text.includes('#EXTM3U') ? 'hls' : 'invalid-hls';
          variants = (text.match(/#EXT-X-STREAM-INF/g) || []).length;
        } else if (/video|octet/i.test(ct) || /\.(mp4|ts)(\?|$)/i.test(target)) kind = 'file';
        else if (/html/i.test(ct)) kind = 'page';
        return json({ ok: (res.ok || res.status === 206) && kind !== 'invalid-hls', status: res.status, kind, variants, contentType: ct, ms: Date.now() - t0 }, 200, cors);
      } catch (e) {
        return json({ ok: false, error: e && e.name === 'AbortError' ? 'timeout' : 'اتصال برقرار نشد', ms: Date.now() - t0 }, 200, cors);
      }
    }

    if (path === '/api/admin/audit' && method === 'GET') {
      return json((await kvGet(env, 'audit').catch(() => null)) || [], 200, cors);
    }

    // سازگاری با پنل قدیمی: ذخیرهٔ کل آرایه (Upsert + حذف موارد غایب)
    if (path === '/api/matches' && method === 'POST') {
      let body; try { body = await readBody(request, 400000); } catch { return err('Invalid JSON body', 400, cors); }
      if (!Array.isArray(body.matches)) return err('Invalid matches array', 400, cors);
      const recs = await listRecords(env);
      const byId = new Map(recs.map(r => [r.id, r]));
      const keep = new Set();
      for (const m of body.matches) {
        const norm = normalizeRecord(m, byId.get(m && m.id) || null);
        if (norm.error) return err(norm.error, 422, cors);
        const rec = norm.value; rec.rev = (byId.get(rec.id)?.rev || 0) + 1; rec.updatedAt = Date.now();
        keep.add(rec.id);
        await kvPut(env, `m:${rec.id}`, rec);
      }
      for (const r of recs) if (!keep.has(r.id)) { await env.MATCHES_STORE.delete(`m:${r.id}`); await env.MATCHES_STORE.delete(`s:${r.id}`); }
      invalidateMemo();
      await audit(env, { action: 'bulk', count: body.matches.length });
      return json({ success: true, count: body.matches.length, timestamp: Date.now() }, 200, cors);
    }

    return err('Not found', 404, cors, { path });
  }

  return err('Not found', 404, cors, { path });
}

export default {
  async fetch(request, env, ctx) {
    try { return await handle(request, env, ctx); }
    catch (e) {
      console.error('unhandled', e && e.stack || e);
      return new Response(JSON.stringify({ error: 'internal_error' }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsFor(request, env) } });
    }
  },
  // Cron (هر دقیقه): گذار وضعیت‌ها را حتی وقتی هیچ بینننده‌ای نیست ثبت می‌کند
  async scheduled(_event, env, ctx) {
    ctx.waitUntil((async () => { invalidateMemo(); await buildAll(env, ctx, 'https://worker.invalid', { includeHidden: true }); })());
  }
};
