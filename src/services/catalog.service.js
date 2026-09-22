const dns = require('dns');
const http = require('http');
const net = require('net');
const productRepo = require('../data/repositories/productRepository');

function isPrivateIPv4(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255 || !Number.isInteger(p))) return true;
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

function parseIPv6(ip) {
    if (!ip || typeof ip !== 'string') return null;
    let s = ip.trim().toLowerCase();

    const zoneIndex = s.indexOf('%');
    if (zoneIndex !== -1) {
        s = s.substring(0, zoneIndex);
    }

    const lastColon = s.lastIndexOf(':');
    if (lastColon === -1) return null;
    const tail = s.substring(lastColon + 1);
    if (tail.includes('.')) {
        const parts = tail.split('.');
        if (parts.length !== 4) return null;
        const nums = parts.map(Number);
        if (nums.some(n => isNaN(n) || n < 0 || n > 255 || !Number.isInteger(n))) return null;
        const w1 = ((nums[0] << 8) | nums[1]).toString(16);
        const w2 = ((nums[2] << 8) | nums[3]).toString(16);
        s = s.substring(0, lastColon + 1) + w1 + ':' + w2;
    }

    let groups;
    if (s.includes('::')) {
        const doubleColonParts = s.split('::');
        if (doubleColonParts.length !== 2) return null;

        const left = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
        const right = doubleColonParts[1] ? doubleColonParts[1].split(':') : [];
        const total = left.length + right.length;
        if (total > 7) return null;

        const missing = 8 - total;
        groups = [...left, ...Array(missing).fill('0'), ...right];
    } else {
        groups = s.split(':');
        if (groups.length !== 8) return null;
    }

    if (groups.length !== 8) return null;

    const words = [];
    for (const g of groups) {
        if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
        const val = parseInt(g, 16);
        if (isNaN(val) || val < 0 || val > 0xffff) return null;
        words.push(val);
    }
    return words;
}

function isPrivateIPv6(ip) {
    const words = parseIPv6(ip);
    if (!words) return true;

    const [w0, w1, w2, w3, w4, w5, w6, w7] = words;

    // Unspecified ::/128
    if (words.every(w => w === 0)) return true;

    // Loopback ::1/128
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && w6 === 0 && w7 === 1) return true;

    // IPv4-mapped IPv6 ::ffff:0:0/96
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0xffff) {
        const ipv4 = [(w6 >> 8) & 0xff, w6 & 0xff, (w7 >> 8) & 0xff, w7 & 0xff].join('.');
        return isPrivateIPv4(ipv4);
    }

    // IPv4-compatible IPv6 ::0:0/96
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0) {
        const ipv4 = [(w6 >> 8) & 0xff, w6 & 0xff, (w7 >> 8) & 0xff, w7 & 0xff].join('.');
        return isPrivateIPv4(ipv4);
    }

    // 6to4 2002::/16
    if (w0 === 0x2002) {
        const ipv4 = [(w1 >> 8) & 0xff, w1 & 0xff, (w2 >> 8) & 0xff, w2 & 0xff].join('.');
        return isPrivateIPv4(ipv4);
    }

    // Teredo 2001:0000::/32
    if (w0 === 0x2001 && w1 === 0x0000) {
        const invW6 = w6 ^ 0xffff;
        const invW7 = w7 ^ 0xffff;
        const ipv4 = [(invW6 >> 8) & 0xff, invW6 & 0xff, (invW7 >> 8) & 0xff, invW7 & 0xff].join('.');
        if (isPrivateIPv4(ipv4)) return true;
    }

    // Well-Known NAT64 prefix 64:ff9b::/96
    if (w0 === 0x0064 && w1 === 0xff9b && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0) {
        const ipv4 = [(w6 >> 8) & 0xff, w6 & 0xff, (w7 >> 8) & 0xff, w7 & 0xff].join('.');
        return isPrivateIPv4(ipv4);
    }

    // Local-Use IPv4/IPv6 Translation 64:ff9b:1::/48
    if (w0 === 0x0064 && w1 === 0xff9b && w2 === 1) {
        const ipv4 = [(w6 >> 8) & 0xff, w6 & 0xff, (w7 >> 8) & 0xff, w7 & 0xff].join('.');
        return isPrivateIPv4(ipv4);
    }

    // Unique Local Address (ULA) fc00::/7 (fc00:: - fdff::)
    if ((w0 & 0xfe00) === 0xfc00) return true;

    // Link-Local Unicast fe80::/10 (fe80:: - febf::)
    if ((w0 & 0xffc0) === 0xfe80) return true;

    // Site-Local Unicast fec0::/10 (deprecated)
    if ((w0 & 0xffc0) === 0xfec0) return true;

    // Multicast ff00::/8
    if ((w0 & 0xff00) === 0xff00) return true;

    // Documentation prefix 2001:db8::/32
    if (w0 === 0x2001 && w1 === 0x0db8) return true;

    // Discard prefix 100::/64
    if (w0 === 0x0100 && w1 === 0 && w2 === 0 && w3 === 0) return true;

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

function safeLookup(hostname, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
        if (err) {
            return callback(err);
        }
        if (!addresses || addresses.length === 0) {
            return callback(new Error("Forbidden access rule triggered."));
        }
        for (const addr of addresses) {
            const ip = addr.address;
            const family = addr.family;
            if (family === 4 && isPrivateIPv4(ip)) {
                return callback(new Error("Forbidden access rule triggered."));
            }
            if (family === 6 && isPrivateIPv6(ip)) {
                return callback(new Error("Forbidden access rule triggered."));
            }
            if (isForbiddenHost(ip)) {
                return callback(new Error("Forbidden access rule triggered."));
            }
        }
        if (options && options.all) {
            return callback(null, addresses);
        }
        return callback(null, addresses[0].address, addresses[0].family);
    });
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
    const requestOptions = typeof reqTarget === 'string' || reqTarget instanceof URL
        ? [reqTarget, { lookup: safeLookup }]
        : [Object.assign({}, reqTarget, { lookup: safeLookup })];

    http.get(...requestOptions, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    }).on('error', err => cb(err));
};
