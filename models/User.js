const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    provider: {
        type: String,
        required: true,
    },
    providerId: {
        type: String,
        required: true,
        unique: true,
    },
    email: {
        type: String,
        required: function () {
            return this.provider !== 'facebook';
        },
        unique: true,
        sparse: true,
    },
    name: {
        type: String,
        required: function () {
            return this.provider !== 'facebook';
        },
    },
    picture: {
        type: String,
    },
    refreshToken: {
        type: String,
    },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

module.exports = User;