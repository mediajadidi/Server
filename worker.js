// ============================================================
// 🔴 AJ SPORTS – Cloudflare Worker v8.0 (Unified)
// 🔴 تمام نیازهای اپلیکیشن + پروکسی استریم پیشرفته
// ============================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // کلید کش برای Cache API
    const cacheUrl = new URL(request.url);
    const cacheKey = new Request(cacheUrl.toString(), request);
    const cache = caches.default;

    // هدرهای CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, admin-token',
      'Access-Control-Max-Age': '86400',
    };

    // مدیریت Preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders, status: 204 });
    }

    // ============================================================
    // 🏠 GET /api
    // ============================================================
    if ((path === '/api' || path === '/') && method === 'GET') {
      return new Response(JSON.stringify({
        status: '🚀 AJ SPORTS API v8.0 (Worker)',
        endpoints: [
          '/api/matches',
          '/api/chat',
          '/api/chat/events',
          '/api/football/:action',
          '/api/stream-proxy',
          '/api/admin/matches'
        ]
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // ============================================================
    // 📡 GET /api/matches – Edge Cache 3s
    // ============================================================
    if (path === '/api/matches' && method === 'GET') {
      let response = await cache.match(cacheKey);
      if (response) {
        response = new Response(response.body, response);
        response.headers.set('X-Cache', 'HIT');
        response.headers.set('Access-Control-Allow-Origin', '*');
        return response;
      }

      let matches = [];
      try {
        const raw = await env.MATCHES_STORE.get('live_matches', { type: 'json' });
        if (raw && Array.isArray(raw)) matches = raw;
      } catch (e) {
        console.error('KV GET error:', e.message);
      }

      response = new Response(JSON.stringify(matches), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'public, max-age=0, s-maxage=3, stale-while-revalidate=5',
          'X-Cache': 'MISS',
          ...corsHeaders
        }
      });

      ctx.waitUntil(cache.put(cacheKey, response.clone()));
      return response;
    }

    // ============================================================
    // 🎯 POST /api/matches – Admin only
    // ============================================================
    if (path === '/api/matches' && method === 'POST') {
      const token = request.headers.get('admin-token') || url.searchParams.get('token') || '';
      const ADMIN_SECRET = env.ADMIN_SECRET || 'Aj2024Secure#';

      if (token !== ADMIN_SECRET) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      try {
        const body = await request.json();
        const matches = body.matches;

        if (!matches || !Array.isArray(matches)) {
          return new Response(JSON.stringify({ error: 'Invalid matches array' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        await env.MATCHES_STORE.put('live_matches', JSON.stringify(matches));

        // Purge Edge Cache
        const purgeUrl = new URL(request.url);
        purgeUrl.pathname = '/api/matches';
        await cache.delete(new Request(purgeUrl.toString()));

        return new Response(JSON.stringify({ 
          success: true, 
          count: matches.length,
          timestamp: Date.now()
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });

      } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
    }

    // ============================================================
    // ⚽ GET /api/football/:action – API Proxy
    // ============================================================
    if (path.startsWith('/api/football/') && method === 'GET') {
      const action = path.replace('/api/football/', '');
      const queryParams = url.searchParams.toString();
      const API_KEY = env.API_KEY_FOOTBALL || '';

      if (!API_KEY) {
        return new Response(JSON.stringify({ error: 'API_KEY_FOOTBALL not set' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 🔴 NEW: برای get_events همیشه timezone=0 (UTC) اجباری می‌کنیم تا match_date/match_time
      // همیشه UTC برگردد و شمارش‌معکوس پیش از بازی/تشخیص نیمه اول-دوم در سمت کلاینت،
      // مستقل از تایم‌زون سرور apifootball و مستقل از کشور بیننده، همیشه درست محاسبه شود.
      // (اگر خودِ کاربر/فرانت یک timezone دیگر در query پاس بدهد، به آن اولویت داده می‌شود.)
      const isEventAction = action === 'get_events';
      const hasTimezoneParam = url.searchParams.has('timezone');
      const tzOverride = (isEventAction && !hasTimezoneParam) ? '&timezone=0' : '';

      const apiUrl = `https://apiv3.apifootball.com/?action=${action}&${queryParams}${tzOverride}&APIkey=${API_KEY}`;
      const fbCacheKey = new Request(`https://fb-cache/${action}?${queryParams}${tzOverride}`, request);

      let fbResponse = await cache.match(fbCacheKey);
      if (fbResponse) {
        fbResponse = new Response(fbResponse.body, fbResponse);
        fbResponse.headers.set('X-Cache', 'HIT');
        fbResponse.headers.set('Access-Control-Allow-Origin', '*');
        return fbResponse;
      }

      try {
        const upstream = await fetch(apiUrl);
        const data = await upstream.json();

        // 🔴 NEW: کش کوتاه‌تر مخصوص get_events (۸ ثانیه به‌جای ۳۰) — چون این اندپوینت منبع
        // اصلی تشخیص لحظه‌ای "نیمه اول → نیمه دوم" و شمارش‌معکوس پیش از بازی است و باید
        // خیلی سریع‌تر از سایر اکشن‌ها (لاین‌آپ، جدول و...) در لبه رفرش شود. همچنان یک
        // درخواست مشترک برای همه‌ی کاربران است، فقط TTL کوتاه‌تر.
        const sMaxAge = isEventAction ? 8 : 30;
        const swr = isEventAction ? 15 : 60;

        fbResponse = new Response(JSON.stringify(data), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': `public, s-maxage=${sMaxAge}, stale-while-revalidate=${swr}`,
            'X-Cache': 'MISS',
            ...corsHeaders
          }
        });

        ctx.waitUntil(cache.put(fbCacheKey, fbResponse.clone()));
        return fbResponse;
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Football API unavailable' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
    }

    // ============================================================
    // 💬 Chat endpoints (GET /api/chat, POST /api/chat, SSE)
    // ============================================================
    if (path === '/api/chat' && method === 'GET') {
      const matchId = url.searchParams.get('match_id') || 'global';
      let messages = [];
      try {
        const raw = await env.MATCHES_STORE.get(`chat_${matchId}`, { type: 'json' });
        if (raw && Array.isArray(raw)) messages = raw;
      } catch (e) {}
      return new Response(JSON.stringify({ messages }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    if (path === '/api/chat' && method === 'POST') {
      try {
        const body = await request.json();
        const { text, email, avatar, reply_text, match_id } = body;
        if (!text || !email) {
          return new Response(JSON.stringify({ error: 'Missing fields' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        const message = {
          id: Date.now().toString(36) + Math.random().toString(36).substring(2, 6),
          text: text.substring(0, 500),
          sender: email.split('@')[0],
          sender_identity_id: email,
          avatar: avatar || '',
          reply_text: reply_text || null,
          match_id: match_id || 'global',
          timestamp: Date.now()
        };

        const key = `chat_${match_id || 'global'}`;
        let messages = [];
        try {
          const raw = await env.MATCHES_STORE.get(key, { type: 'json' });
          if (raw && Array.isArray(raw)) messages = raw;
        } catch (e) {}

        messages.unshift(message);
        messages = messages.slice(0, 100);
        await env.MATCHES_STORE.put(key, JSON.stringify(messages));

        return new Response(JSON.stringify({ success: true, message }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
    }

    if (path === '/api/chat/events' && method === 'GET') {
      const matchId = url.searchParams.get('match_id') || 'global';
      const stream = new ReadableStream({
        async start(controller) {
          const encoder = new TextEncoder();
          let lastCheck = Date.now();

          const sendHeartbeat = () => {
            controller.enqueue(encoder.encode(`: heartbeat ${Date.now()}\n\n`));
          };

          const checkMessages = async () => {
            try {
              const raw = await env.MATCHES_STORE.get(`chat_${matchId}`, { type: 'json' });
              if (raw && Array.isArray(raw)) {
                const newMessages = raw.filter(m => m.timestamp > lastCheck);
                for (const msg of newMessages) {
                  controller.enqueue(encoder.encode(
                    `data: ${JSON.stringify({ type: 'message', payload: msg })}\n\n`
                  ));
                }
              }
              lastCheck = Date.now();
            } catch (e) {}
          };

          await checkMessages();
          const heartbeatInterval = setInterval(sendHeartbeat, 30000);
          const checkInterval = setInterval(checkMessages, 2000);

          request.signal.addEventListener('abort', () => {
            clearInterval(heartbeatInterval);
            clearInterval(checkInterval);
          });
        }
      });

      return new Response(stream, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*',
          'X-Accel-Buffering': 'no'
        }
      });
    }

    // ============================================================
    // 📡 پروکسی استریم M3U8/TS (رفع 403، CORS، HTTP)
    // ============================================================
    if (path === '/api/stream-proxy' && method === 'GET') {
      const targetUrl = url.searchParams.get('url');
      if (!targetUrl) {
        return new Response(JSON.stringify({ error: 'Missing url param' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      try {
        // استخراج Referer از خود URL هدف (یا دریافت سفارشی)
        let referer = url.searchParams.get('referer');
        if (!referer) {
          try {
            const parsed = new URL(targetUrl);
            referer = `${parsed.protocol}//${parsed.host}/`;
          } catch {
            referer = 'https://ajsportstv.netlify.app/'; // fallback
          }
        }

        // شبیه‌سازی دقیق مرورگر برای عبور از 403 و محدودیت‌ها
        const response = await fetch(targetUrl, {
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9,fa;q=0.8',
            'Origin': referer,
            'Referer': referer,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
          },
          redirect: 'follow',
        });

        if (!response.ok) {
          return new Response(JSON.stringify({ error: 'Upstream error', status: response.status }), {
            status: 502,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        const responseHeaders = new Headers();
        responseHeaders.set('Content-Type', response.headers.get('content-type') || 'application/vnd.apple.mpegurl');
        responseHeaders.set('Access-Control-Allow-Origin', '*');
        responseHeaders.set('Cache-Control', 'public, max-age=5');

        return new Response(response.body, {
          status: 200,
          headers: responseHeaders,
        });

      } catch (e) {
        return new Response(JSON.stringify({ error: 'Proxy failed: ' + e.message }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
    }

    // ============================================================
    // 🔴 404
    // ============================================================
    return new Response(JSON.stringify({ error: 'Not found', path }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
};
