// Vercel Routing Middleware: password-protects the whole site with HTTP Basic auth.
// Set SITE_USER and SITE_PASSWORD in Vercel → Settings → Environment Variables, then redeploy.
// Fails closed: without both variables nothing is served.
export const config = { matcher: '/(.*)' };

const REALM = 'Bharat Harvest supplier research';

// Constant-time comparison so response timing does not leak how much of a guess matched.
function safeEqual(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

export default function middleware(request) {
  const user = process.env.SITE_USER;
  const pass = process.env.SITE_PASSWORD;
  if (!user || !pass) {
    return new Response('Site locked: the owner has not configured access yet.', { status: 503 });
  }

  const [scheme, encoded] = (request.headers.get('authorization') || '').split(' ');
  if (scheme === 'Basic' && encoded) {
    let decoded = '';
    try { decoded = atob(encoded); } catch { /* malformed header */ }
    const sep = decoded.indexOf(':');
    if (sep > -1 && safeEqual(decoded.slice(0, sep), user) && safeEqual(decoded.slice(sep + 1), pass)) {
      return; // authorised: continue to the static page
    }
  }

  return new Response('Authentication required.', {
    status: 401,
    headers: { 'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`, 'Cache-Control': 'no-store' },
  });
}
