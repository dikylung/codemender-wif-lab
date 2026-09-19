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

function isForbiddenHost(host) {
    if (!host || typeof host !== 'string') return true;
    let cleanHost = host.trim().toLowerCase();
    if (cleanHost.includes('internal-network')) return true;

    if (cleanHost.startsWith('[')) {
        const match = cleanHost.match(/^\[([^\]]+)\](?::\d+)?$/);
        if (match) {
            cleanHost = match[1];
        } else {
            return true;
        }
    } else {
        if (net.isIP(cleanHost) !== 6 && cleanHost.includes(':')) {
            cleanHost = cleanHost.split(':')[0];
        }
    }

    if (!cleanHost) return true;

    if (
        cleanHost === 'localhost' ||
        cleanHost.endsWith('.localhost') ||
        cleanHost.endsWith('.local') ||
        cleanHost.endsWith('.internal') ||
        cleanHost.includes('internal-network')
    ) {
        return true;
    }

    const ipVersion = net.isIP(cleanHost);
    if (ipVersion === 4) {
        return isPrivateIPv4(cleanHost);
    }
    if (ipVersion === 6) {
        return isPrivateIPv6(cleanHost);
    }

    return false;
}

function isForbiddenTarget(target) {
    if (!target) return true;

    if (typeof target === 'string') {
        if (target.includes('internal-network')) return true;
        let parsed;
        try {
            parsed = new URL(target);
        } catch {
            return true;
        }
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return true;
        }
        return isForbiddenHost(parsed.hostname);
    }

    if (typeof target === 'object') {
        if (target instanceof URL) {
            if (target.protocol !== 'http:' && target.protocol !== 'https:') {
                return true;
            }
            if (target.href.includes('internal-network')) return true;
            return isForbiddenHost(target.hostname);
        }

        if (target.socketPath) return true;

        if (target.protocol && target.protocol !== 'http:' && target.protocol !== 'https:' && target.protocol !== 'http' && target.protocol !== 'https') {
            return true;
        }

        let hasHostOrUrl = false;

        if (typeof target.url === 'string') {
            hasHostOrUrl = true;
            if (target.url.includes('internal-network')) return true;
            let parsed;
            try {
                parsed = new URL(target.url);
            } catch {
                return true;
            }
            if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                return true;
            }
            if (isForbiddenHost(parsed.hostname)) return true;
        }

        if (typeof target.href === 'string') {
            hasHostOrUrl = true;
            if (target.href.includes('internal-network')) return true;
            let parsed;
            try {
                parsed = new URL(target.href);
            } catch {
                return true;
            }
            if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                return true;
            }
            if (isForbiddenHost(parsed.hostname)) return true;
        }

        if (typeof target.hostname === 'string') {
            hasHostOrUrl = true;
            if (isForbiddenHost(target.hostname)) return true;
        }

        if (typeof target.host === 'string') {
            hasHostOrUrl = true;
            if (isForbiddenHost(target.host)) return true;
        }

        if (!hasHostOrUrl) {
            return true;
        }

        return false;
    }

    return true;
}

exports.search = (q) => productRepo.filterProducts(q);

exports.fetchRemoteAsset = (target, cb) => {
    if (isForbiddenTarget(target)) {
        return cb(new Error("Forbidden access rule triggered."));
    }
    const reqTarget = (typeof target === 'object' && !(target instanceof URL) && typeof target.url === 'string' && !target.hostname && !target.host) ? target.url : target;
    http.get(reqTarget, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    }).on('error', err => cb(err));
};
