const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    provider: {
        type: String,
        required: true,
        enum: ['google', 'facebook', 'github'] // Assurer que le provider est l'un des services supportés
    },
    providerId: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: function () {
            return this.provider !== 'facebook';
        },
        sparse: true, // Permet des emails non-uniques pour les utilisateurs Facebook
        lowercase: true, // Normalise les emails
        trim: true // Supprime les espaces
    },
    name: {
        type: String,
        required: function () {
            return this.provider !== 'facebook';
        },
        trim: true
    },
    picture: {
        type: String,
    },
    refreshToken: {
        type: String,
    },
    // Champs supplémentaires pour OpenID Connect
    sub: { // subject identifier - identifiant unique de l'utilisateur
        type: String,
        unique: true,
        sparse: true
    },
    emailVerified: {
        type: Boolean,
        default: false
    },
    locale: String,
    givenName: String,
    familyName: String,
    // Permissions et rôles
    roles: {
        type: [String],
        default: ['user'],
        enum: ['user', 'admin']
    },
    // Métadonnées de compte
    lastLogin: Date,
    active: {
        type: Boolean,
        default: true
    },
    // Index composé pour assurer l'unicité providerId+provider
    createdAt: Date,
    updatedAt: Date
}, { 
    timestamps: true,
    toJSON: { 
        transform: function(doc, ret) {
            delete ret.refreshToken; // Ne jamais exposer le refreshToken
            return ret;
        }
    } 
});

// Index composé pour rechercher rapidement par provider et providerId
userSchema.index({ provider: 1, providerId: 1 }, { unique: true });

// Méthode d'instance pour générer un objet de profil compatible OpenID Connect
userSchema.methods.toOpenIDProfile = function() {
    return {
        sub: this.sub || this._id.toString(),
        name: this.name,
        given_name: this.givenName,
        family_name: this.familyName,
        picture: this.picture,
        email: this.email,
        email_verified: this.emailVerified,
        locale: this.locale,
        updated_at: this.updatedAt ? Math.floor(this.updatedAt.getTime() / 1000) : undefined
    };
};

const User = mongoose.model('User', userSchema);

module.exports = User;