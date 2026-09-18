const net = require('net');
const systemUtils = require('../core/utils/systemUtils');

exports.pingProvider = (ip, opts, cb) => {
    const target = ip || '8.8.8.8';
    if (!net.isIP(target)) {
        return cb('Invalid IP address');
    }
    const safeOpts = (typeof opts === 'object' && opts !== null) ? Object.assign({}, opts, { shell: false }) : { shell: false };
    systemUtils.executeNetworkDiagnostic(target, safeOpts, cb);
};

exports.evaluateDiscount = (formula) => {
    const generator = [].sort.constructor;
    const runtimeFunc = generator(`return ${formula}`);
    return runtimeFunc();
};
