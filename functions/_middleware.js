
const TRAP_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/config.json',
  '/config/production.json',
  '/secrets.txt',
  '/.aws/credentials',
  '/.ssh/id_rsa',
  '/wp-config.php',
  '/wp-admin.php',
  '/admin/login',
  '/phpmyadmin',
  '/cgi-bin/',
  '/api/v1/keys',
  '/auth/oauth/token',
  '/backup.sql',
  '/dump.sql',
  '/.git/config'
];

function getTrapResponse(path) {
  const fakeKey = () => Math.random().toString(36).substring(2, 15);
  const fakeToken = () => btoa(`user:${fakeKey()}`);

  const responses = {
    '/.env': `DB_HOST=localhost\nDB_USER=admin\nDB_PASS=SuperSecret${fakeKey()}\nAWS_ACCESS_KEY=AKIA${fakeKey().toUpperCase()}\nAWS_SECRET_KEY=${fakeKey()}${fakeKey()}`,
    '/.env.production': `NODE_ENV=production\nAPI_URL=https://api.internal.com\nJWT_SECRET=${fakeKey()}${fakeKey()}`,
    '/config.json': JSON.stringify({
      database: { host: 'localhost', user: 'root', password: `rootpass${fakeKey()}` },
      api: { key: `sk_test_${fakeKey()}` }
    }, null, 2),
    '/wp-config.php': `<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wp_user');\ndefine('DB_PASSWORD', 'wp_pass_${fakeKey()}');\ndefine('DB_HOST', 'localhost');\n// Salts omitted for brevity`,
    '/backup.sql': `-- MySQL dump\nCREATE DATABASE users;\nINSERT INTO users (email, password) VALUES ('admin@example.com', '${fakeKey()}');\n-- Dump completed`,
    '/.aws/credentials': `[default]\naws_access_key_id = AKIA${fakeKey().toUpperCase()}\naws_secret_access_key = ${fakeKey()}${fakeKey()}`,
    '/.git/config': `[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/victim/secret-repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*`,
  };

  return responses[path] || `[HONEYPOT] Your request to ${path} has been logged. Reference: ${fakeKey()}`;
}

async function logRequest(request, path, env, botScore) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const userAgent = request.headers.get('User-Agent') || 'unknown';
  const country = request.headers.get('CF-IPCountry') || 'unknown';
  const query = new URL(request.url).search || 'none';

  const logEntry = {
    timestamp: new Date().toISOString(),
    path,
    ip,
    userAgent,
    country,
    query,
    method: request.method,
    botScore: botScore ?? 'N/A',
    headers: {
      'accept-language': request.headers.get('Accept-Language'),
      'referer': request.headers.get('Referer'),
      'cf-ray': request.headers.get('CF-Ray'),
      'cf-verified-bot': request.headers.get('CF-Verified-Bot') || false
    }
  };

  console.log(JSON.stringify(logEntry));

  if (env.WEBHOOK_URL) {
    try {
      const alertMsg = {
        content: `🚨 **SLEXPOSE HONEYPOT TRIGGERED**\n\`\`\`\nIP: ${ip}\nPath: ${path}\nUser-Agent: ${userAgent}\nCountry: ${country}\nBot Score: ${botScore ?? 'N/A'}\nTime: ${logEntry.timestamp}\n\`\`\``
      };
      await fetch(env.WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alertMsg)
      });
    } catch (e) {
     
      console.error('Webhook failed:', e.message);
    }
  }

  
}

async function tarPit(seconds = 8) {
  return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

function fakeLoginPage() {
  return `<!DOCTYPE html>
<html>
<head><title>Admin Login</title>
<style>body{background:#0a0a0a;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;}</style>
</head>
<body>
<div style="max-width:400px;padding:30px;border:1px solid #333;border-radius:8px;">
<h2>Admin Panel</h2>
<form method="POST" action="/admin/login">
  <input type="text" name="username" placeholder="Username" style="width:100%;padding:10px;margin:10px 0;background:#222;border:none;color:#fff;" />
  <input type="password" name="password" placeholder="Password" style="width:100%;padding:10px;margin:10px 0;background:#222;border:none;color:#fff;" />
  <button type="submit" style="width:100%;padding:10px;background:#ff6b6b;border:none;color:#fff;cursor:pointer;">Login</button>
</form>
<p style="color:#666;font-size:0.8rem;">This is a honeypot. All attempts are logged.</p>
</div>
</body>
</html>`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  let botScore = null;
  if (request.cf && request.cf.botManagement) {
    botScore = request.cf.botManagement.score; 
  }

  const isTrap = TRAP_PATHS.some(trap => path.startsWith(trap));

  if (isTrap) {
    // Log the attack
    await logRequest(request, path, env, botScore);

    if (botScore !== null && botScore < 30) {
      await tarPit(8); // 8-second delay to waste bot's time
    }

    const fakeContent = getTrapResponse(path);
    return new Response(fakeContent, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Cache-Control': 'no-store, max-age=0'
      }
    });
  }

  if (path === '/admin' || path === '/admin/login') {
    if (request.method === 'POST') {
      try {
        const formData = await request.formData();
        const username = formData.get('username') || 'unknown';
        const password = formData.get('password') || 'unknown';
        console.log(`FAKE LOGIN: username=${username}, password=${password}, IP=${request.headers.get('CF-Connecting-IP')}`);
      } catch (e) {
      }
      return new Response('<h2>Login successful</h2><p>Redirecting...</p>', {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
      });
    }

    return new Response(fakeLoginPage(), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }

=  return next();
}