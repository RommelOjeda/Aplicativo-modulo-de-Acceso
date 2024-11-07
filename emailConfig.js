const nodemailer = require('nodemailer');

// Configura el transporter de email (ejemplo con Gmail)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'rommelfake4@gmail.com', 
        pass: 'phgj cynd qfvw sxjt'
    }
});

const sendVerificationCode = async (email, code) => {
    try {
        await transporter.sendMail({
            from: 'tu_correo@gmail.com',
            to: email,
            subject: 'Código de verificación',
            text: `Tu código de verificación es: ${code}`,
            html: `<h1>Código de verificación</h1><p>Tu código de verificación es: <strong>${code}</strong></p>`
        });
        return true;
    } catch (error) {
        console.error('Error enviando email:', error);
        return false;
    }
};

module.exports = { sendVerificationCode };