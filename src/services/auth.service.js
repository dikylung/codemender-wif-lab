const userRepository = require('../data/repositories/userRepository');
const cryptoUtils = require('../core/utils/cryptoUtils');

exports.resetPasswordToken = () => {
    return cryptoUtils.generateSessionContextId();
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
