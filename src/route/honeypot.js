'use strict';

/**
 * Honeypot endpoints — decoy interfaces that appear vulnerable but log + alert.
 * Any interaction is presumed malicious and recorded as critical-severity.
 */

const HONEYPOTS = {
  '/admin.php': {
    method: 'ANY',
    respond: (req) => ({
      content_type: 'text/html',
      body: '<!DOCTYPE html><html><head><title>Admin Login</title></head>' +
        '<body><form method="post" action="/admin.php">' +
        '<input type="hidden" name="debug_token" value="demo_token_1234">' +
        '<label>Username <input name="username"></label>' +
        '<label>Password <input name="password" type="password"></label>' +
        '<button>Login</button></form></body></html>'
    })
  },
  '/.env': {
    method: 'ANY',
    respond: () => ({
      content_type: 'text/plain',
      body: 'DB_HOST=10.0.4.21\nDB_PORT=5432\nDB_NAME=novapay_prod\n' +
        'DB_USER=prod_admin\nDB_PASSWORD=demo_password_placeholder\n' +
        'JWT_SECRET=demo_jwt_secret_placeholder\n' +
        'AWS_ACCESS_KEY=demo_aws_key_placeholder\n' +
        'AWS_SECRET_KEY=demo_aws_secret_placeholder\n' +
        'REDIS_URL=redis://10.0.4.22:6379\nAPI_STRIPE_KEY=demo_stripe_key_placeholder'
    })
  },
  '/.git/config': {
    method: 'ANY',
    respond: () => ({
      content_type: 'text/plain',
      body: '[core]\n\trepositoryformatversion = 0\n' +
        '[remote "origin"]\n\turl = git@github.com:novapay/internal-payments.git\n' +
        '\tfetch = +refs/heads/*:refs/remotes/origin/*\n' +
        '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n' +
        '[user]\n\tname = deploy-bot\n\temail = deploy@novapay.internal'
    })
  },
  '/wp-login.php': {
    method: 'ANY',
    respond: () => ({
      content_type: 'text/html',
      body: '<!DOCTYPE html><html><body>' +
        '<form method="post"><input name="log"><input name="pwd" type="password">' +
        '<button>Log In</button></form></body></html>'
    })
  },
  '/api/debug': {
    method: 'ANY',
    respond: (req) => ({
      content_type: 'application/json',
      body: JSON.stringify({
        status: 'ok',
        debug: {
          sql_last: 'SELECT id, username, password_hash, balance FROM users WHERE id = ?',
          memory: '48MB / 512MB',
          pid: 1337,
          php_version: '8.2.18',
          env: 'development'
        },
        config: db_config_bait()
      }, null, 2)
    })
  },
  '/phpmyadmin/': {
    method: 'ANY',
    respond: () => ({
      content_type: 'text/html',
      body: '<!DOCTYPE html><head><title>phpMyAdmin 5.2.1</title></head>' +
        '<body><form method="post" name="login_form">' +
        '<input name="pma_username"><input name="pma_password" type="password">' +
        '<input type="hidden" name="server" value="1">' +
        '<button>Go</button></form></body></html>'
    })
  }
};

function db_config_bait() {
  return {
    database: { host: '10.0.4.21', name: 'novapay_prod' },
    admin: { user: 'root', pass: 'R00t_D3v_2024' }
  };
}

function isHoneypotPath(url) {
  // Try raw, then try normalized (strip trailing slash)
  if (HONEYPOTS[url]) return HONEYPOTS[url];
  const norm = url.replace(/\/+$/, '') || '/';
  return HONEYPOTS[norm] || false;
}

function handleHoneypot(req, res, logger) {
  const ep = isHoneypotPath(req.url);
  if (!ep) return false;

  const ip = req.socket.remoteAddress || 'unknown';
  logger.log({
    ip,
    ua: req.headers['user-agent'] || 'unknown',
    route: req.url,
    action: 'HONEYPOT_HIT',
    rule: `HONEYPOT_${req.url.replace(/\//g, '_')}`,
    severity: 'critical',
    payload_hash: ''
  });

  const out = ep.respond(req);
  res.setHeader('Content-Type', out.content_type);
  res.setHeader('X-Honey-Trap', 'triggered');
  res.writeHead(200);
  res.end(out.body);
  return true;
}

module.exports = { isHoneypotPath, handleHoneypot };
