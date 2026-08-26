// ============================================================
// SLEXPOSE – Pages Function (Middleware) with Honeypot
// This runs on Cloudflare Pages BEFORE static assets are served
// ============================================================

// -------- HONEYPOT PATHS -------------------------------------
const TRAP_PATHS = [
  '/.env',
  '/.env.local',
  '/wp-config.php',
  '/wp-admin.php',
  '/config.json',
  '/backup.sql',
  '/dump.sql',
  '/.git/config',
  '/admin/login',
  '/phpmyadmin',
  '/cgi-bin/',
  '/api/v1/keys',
  '/secrets.txt'
];

// -------- FAKE RESPONSES FOR EACH TRAP -----------------------
function getTrapResponse(path) {
  const fakeData = {
    '/.env': `DB_HOST=localhost\nDB_USER=admin\nDB_PASS=SuperSecret123!\nAWS_ACCESS_KEY=AKIAFAKEKEY123456\nAWS_SECRET_KEY=fakeSecretKeyABCDEFGHIJKLMNOP`,
    '/wp-config.php': `<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wp_user');\ndefine('DB_PASSWORD', 'wp_pass_123');\ndefine('DB_HOST', 'localhost');`,
    '/config.json': `{"database":{"host":"localhost","user":"root","password":"rootpass123"},"api":{"key":"sk_test_4eC39HqLyjWDarjtT1zdp7dc"}}`,
    '/backup.sql': `-- MySQL dump\nCREATE DATABASE users;\nINSERT INTO users (email, password) VALUES ('admin@example.com', 'admin123');`,
    '/.git/config': `[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/victim/secret-repo.git`,
  };
  return fakeData[path] || `[HONEYPOT] Your request to ${path} has been logged.`;
}

// -------- LOGGING FUNCTION ------------------------------------
async function logRequest(request, path, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const userAgent = request.headers.get('User-Agent') || 'unknown';
  const country = request.headers.get('CF-IPCountry') || 'unknown';
  
  const logEntry = {
    timestamp: new Date().toISOString(),
    path,
    ip,
    userAgent,
    country,
    method: request.method
  };
  
  // Logs appear in Cloudflare Pages dashboard under "Functions" logs
  console.log(JSON.stringify(logEntry));
  
  // OPTIONAL: Store in KV (if you set one up)
  // if (env.SLEXPOSE_LOGS) {
  //   await env.SLEXPOSE_LOGS.put(`log:${Date.now()}`, JSON.stringify(logEntry));
  // }
}

// -------- MAIN MIDDLEWARE HANDLER ----------------------------
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // --- 1. Check if this is a honeypot path ---
  const isTrap = TRAP_PATHS.some(trap => path.startsWith(trap));
  if (isTrap) {
    await logRequest(request, path, env);
    
    const fakeContent = getTrapResponse(path);
    return new Response(fakeContent, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
      }
    });
  }

  // --- 2. NOT a trap: let Pages serve the static file normally ---
  // This will serve your index.html for '/', or 404 for other paths
  return next();
}
