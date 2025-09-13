const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const fs = require('fs');

const args = process.argv.slice(2);
if (args.length !== 4) {
    console.error('Usage: filter_proxy <target_url> <listen_host:port> <public_hostname:port> <allowlist_file>');
    console.error('Example: filter_proxy http://example.com 0.0.0.0:8080 proxy.example.com:8080 allowlist.txt');
    process.exit(1);
}

const [targetUrl, listenAddress, publicAddress, allowlistFile] = args;
const [listenHost, listenPort] = listenAddress.split(':');

function loadAllowlist(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));

        return lines.map(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length !== 3) {
                console.log(parts);
                throw new Error(`Invalid rule format: ${line}. Expected: <ALLOW|DENY> <METHOD> <PATH>`);
            }
            const [action, method, pathPattern] = parts;
            const regexPattern = pathPattern
                .replace(/\*/g, '.*')
                .replace(/\?/g, '\\?');
            return {
                action: action.toUpperCase(),
                method: method.toUpperCase(),
                path: new RegExp(`^${regexPattern}$`)
            };
        });
    } catch (error) {
        console.error(`Error loading allowlist: ${error.message}`);
        process.exit(1);
    }
}

const allowlist = loadAllowlist(allowlistFile);

const app = express();

app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);

    // Default is DENY, check rules from top to bottom
    let decision = 'DENY';
    let matchedRule = null;

    for (const rule of allowlist) {
        if (rule.method === req.method && rule.path.test(req.path)) {
            decision = rule.action;
            matchedRule = rule;
        }
    }

    if (decision === 'DENY') {
        if (matchedRule) {
            console.log(`  → DENIED (matched deny rule)`);
        } else {
            console.log(`  → DENIED (default policy, no matching rule)`);
        }
        return res.status(403).json({ error: 'Forbidden: Access denied' });
    }

    console.log(`  → ALLOWED`);
    next();
});

const proxyMiddleware = createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    followRedirects: false,
    on: {
        proxyRes: (proxyRes, req, res) => {
            if (proxyRes.headers.location) {
                const originalLocation = proxyRes.headers.location;
                try {
                    const locationUrl = new URL(originalLocation, targetUrl);
                    const targetHost = new URL(targetUrl).host;

                    if (locationUrl.host === targetHost) {
                        // Use the public address for redirects
                        locationUrl.host = publicAddress;
                        // Keep the protocol as http since we're not using SSL
                        locationUrl.protocol = 'http:';
                        proxyRes.headers.location = locationUrl.toString();
                        console.log(`  → Redirecting to: ${locationUrl.toString()}`);
                    }
                } catch (e) {
                    console.error('Error parsing location header:', e);
                }
            }
        }
    }
});

app.use('/', proxyMiddleware);

app.listen(parseInt(listenPort), listenHost, () => {
    console.log(`Proxy server listening on ${listenAddress}`);
    console.log(`Public access URL: http://${publicAddress}`);
    console.log(`Forwarding allowed requests to ${targetUrl}`);
    console.log(`Loaded ${allowlist.length} rules from ${allowlistFile}`);
});