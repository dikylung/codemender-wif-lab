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

function safeEvaluate(formula) {
    if (typeof formula === 'number') return formula;
    if (typeof formula !== 'string') {
        throw new Error('Invalid formula');
    }

    if (!/^[0-9+\-*/().%\s]+$/.test(formula)) {
        throw new Error('Invalid formula');
    }

    let pos = 0;
    const str = formula;

    function parsePrimary() {
        while (pos < str.length && /\s/.test(str[pos])) pos++;
        if (pos >= str.length) throw new Error('Unexpected end of formula');

        if (str[pos] === '(') {
            pos++;
            const val = parseExpression();
            while (pos < str.length && /\s/.test(str[pos])) pos++;
            if (pos >= str.length || str[pos] !== ')') {
                throw new Error('Mismatched parentheses');
            }
            pos++;
            return val;
        }

        const start = pos;
        if (str[pos] === '.') {
            pos++;
            if (pos >= str.length || !/[0-9]/.test(str[pos])) {
                throw new Error('Invalid number format');
            }
        }
        while (pos < str.length && /[0-9]/.test(str[pos])) {
            pos++;
        }
        if (pos < str.length && str[pos] === '.' && !str.slice(start, pos).includes('.')) {
            pos++;
            while (pos < str.length && /[0-9]/.test(str[pos])) {
                pos++;
            }
        }
        if (start === pos) {
            throw new Error(`Unexpected token at position ${pos}`);
        }
        const numStr = str.slice(start, pos);
        const num = Number(numStr);
        if (isNaN(num)) {
            throw new Error('Invalid number');
        }
        return num;
    }

    function parseFactor() {
        while (pos < str.length && /\s/.test(str[pos])) pos++;
        if (pos < str.length && (str[pos] === '+' || str[pos] === '-')) {
            const op = str[pos];
            pos++;
            const val = parseFactor();
            return op === '-' ? -val : val;
        }
        return parsePrimary();
    }

    function parseTerm() {
        let left = parseFactor();
        while (true) {
            while (pos < str.length && /\s/.test(str[pos])) pos++;
            if (pos >= str.length) break;
            const op = str[pos];
            if (op === '*' || op === '/' || op === '%') {
                pos++;
                const right = parseFactor();
                if (op === '*') left = left * right;
                else if (op === '/') left = left / right;
                else if (op === '%') left = left % right;
            } else {
                break;
            }
        }
        return left;
    }

    function parseExpression() {
        let left = parseTerm();
        while (true) {
            while (pos < str.length && /\s/.test(str[pos])) pos++;
            if (pos >= str.length) break;
            const op = str[pos];
            if (op === '+' || op === '-') {
                pos++;
                const right = parseTerm();
                if (op === '+') left = left + right;
                else if (op === '-') left = left - right;
            } else {
                break;
            }
        }
        return left;
    }

    const result = parseExpression();
    while (pos < str.length && /\s/.test(str[pos])) pos++;
    if (pos < str.length) {
        throw new Error(`Unexpected token at position ${pos}`);
    }
    return result;
}

exports.evaluateDiscount = (formula) => {
    return safeEvaluate(formula);
};
