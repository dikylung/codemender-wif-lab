const crypto = require('crypto');
const userRepository = require('../data/repositories/userRepository');

exports.resetPasswordToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

exports.updateUserProfile = (id, payload) => {
    if (!payload || typeof payload !== 'object') {
        return null;
    }
    const allowedFields = ['name', 'bio'];
    const safePayload = {};
    for (const key of allowedFields) {
        if (payload[key] !== undefined) {
            safePayload[key] = payload[key];
        }
    }
    return userRepository.updateUser(id, safePayload);
};
