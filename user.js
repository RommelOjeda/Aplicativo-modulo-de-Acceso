const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const saltRounds = 10;

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    twoFactorCode: String,
    twoFactorCodeExpires: Date,
    isVerified: { type: Boolean, default: false },
    role: { type: String, enum: ['ADMIN', 'USER'], default: 'USER' }
});

UserSchema.pre('save', function(next) {
    if (this.isNew || this.isModified('password')) {
        const document = this;
        bcrypt.hash(document.password, saltRounds, (err, hashedPassword) => {
            if (err) {
                next(err);
            } else {
                document.password = hashedPassword;
                next();
            }
        });
    } else {
        next();
    }
});

UserSchema.methods.isCorrectPassword = async function(password) {
    try {
        const same = await bcrypt.compare(password, this.password);
        return same;
    } catch (err) {
        throw err;
    }
};

UserSchema.methods.generateVerificationCode = function() {
    const code = Math.floor(100000 + Math.random() * 900000).toString(); // Código de 6 dígitos
    this.twoFactorCode = code;
    this.twoFactorCodeExpires = Date.now() + 600000; // 10 minutos de expiración
    console.log('Código generado:', code);
    console.log('Tiempo de expiración:', this.twoFactorCodeExpires);
    return code;
};

UserSchema.methods.verifyCode = function(code) {
    return this.twoFactorCode === code && Date.now() < this.twoFactorCodeExpires;
};

// Método para verificar permisos de rol
UserSchema.methods.hasRole = function(role) {
    return this.role === role;
};

module.exports = mongoose.model('User', UserSchema);
