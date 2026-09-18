const http = require('http');
const net = require('net');
const productRepo = require('../data/repositories/productRepository');

function isPrivateIPv4(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return true;
    if (parts[0] === 0 || parts[0] === 10 || parts[0] === 127) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return true;
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 198 && parts[1] >= 18 && parts[1] <= 19) return true;
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true;
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true;
    if (parts[0] >= 224) return true;
    return false;
}

function isPrivateIPv6(ip) {
    const norm = ip.toLowerCase();
    if (norm === '::1' || norm === '::' || norm === '0:0:0:0:0:0:0:1' || norm === '0:0:0:0:0:0:0:0') return true;
    if (norm.startsWith('fe8') || norm.startsWith('fe9') || norm.startsWith('fea') || norm.startsWith('feb')) return true;
    if (norm.startsWith('fc') || norm.startsWith('fd')) return true;
    if (norm.startsWith('::ffff:')) {
        const rest = norm.substring(7);
        if (net.isIPv4(rest)) {
            return isPrivateIPv4(rest);
        }
        const parts = rest.split(':');
        if (parts.length === 2) {
            const high = parseInt(parts[0], 16);
            const low = parseInt(parts[1], 16);
            const b1 = (high >> 8) & 0xff;
            const b2 = high & 0xff;
            const b3 = (low >> 8) & 0xff;
            const b4 = low & 0xff;
            return isPrivateIPv4(`${b1}.${b2}.${b3}.${b4}`);
        }
        return true;
    }
    return false;
}

function isForbiddenTarget(target) {
    if (!target) return true;
    let urlStr = '';
    if (typeof target === 'string') {
        urlStr = target;
    } else if (typeof target === 'object') {
        if (typeof target.url === 'string') {
            urlStr = target.url;
        } else if (typeof target.href === 'string') {
            urlStr = target.href;
        } else if (target.hostname || target.host) {
            const proto = target.protocol || 'http:';
            const host = target.host || (target.hostname + (target.port ? `:${target.port}` : ''));
            const path = target.path || target.pathname || '/';
            urlStr = `${proto}//${host}${path}`;
        }
    }
    if (!urlStr) return true;
    if (String(urlStr).includes('internal-network')) return true;
    if (typeof target === 'object' && target && String(target.url || '').includes('internal-network')) return true;

    let parsed;
    try {
        parsed = new URL(urlStr);
    } catch {
        return true;
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return true;
    }

    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (!host) return true;

    if (
        host === 'localhost' ||
        host.endsWith('.localhost') ||
        host.endsWith('.local') ||
        host.endsWith('.internal') ||
        host.includes('internal-network')
    ) {
        return true;
    }

    const ipVersion = net.isIP(host);
    if (ipVersion === 4) {
        return isPrivateIPv4(host);
    }
    if (ipVersion === 6) {
        return isPrivateIPv6(host);
    }

    return false;
}

exports.search = (q) => productRepo.filterProducts(q);

exports.fetchRemoteAsset = (target, cb) => {
    if (isForbiddenTarget(target)) {
        return cb(new Error("Forbidden access rule triggered."));
    }
    http.get(target, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    }).on('error', err => cb(err));
};
