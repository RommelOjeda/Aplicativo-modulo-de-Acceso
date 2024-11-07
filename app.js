const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./user');
const { sendVerificationCode } = require('./emailConfig');

const app = express();
const JWT_SECRET = 'tu_clave_secreta_muy_segura';

// Middleware para verificar el token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No se proporcionó token de acceso' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Token inválido o expirado' });
    }
};

// Middleware para verificar roles
const checkRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Usuario no autenticado' });
        }

        if (roles.includes(req.user.role)) {
            next();
        } else {
            res.status(403).json({ message: 'No tienes permiso para acceder' });
        }
    };
};

/*
mongoose.connect('mongodb://localhost:27017/todos', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Conexión a MongoDB establecida'))
    .catch(err => console.error('Error conectando a MongoDB:', err));
*/

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(__dirname + '/public'));
/*
app.use(session({
    secret: 'cero0', // Cambia a una clave segura
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Cambia a true si usas HTTPS
}));
*/

const mongo_uri = 'mongodb://localhost:27017/todos';

async function connectDB() {
    try {
        await mongoose.connect(mongo_uri, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log(`Successfully connected to ${mongo_uri}`);
    } catch (err) {
        console.error('Error al conectar a la base de datos:', err);
    }
}

connectDB();

app.post('/register', async (req, res) => {
    const { username, password, email, role } = req.body; 

    const user = new User({ username, password, email, role }); // Guardar rol en el nuevo usuario

    try {
        await user.save();
        res.status(200).json({ 
            message: 'USUARIO REGISTRADO',
            redirect: '/index.html'
        });
    } catch (err) {
        res.status(500).json({ 
            message: 'ERROR AL REGISTRAR EL USUARIO',
            redirect: '/signup.html'
        });
    }
});

app.post('/authenticate', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({ error: 'USUARIO NO EXISTE' });
        }

        const isPasswordCorrect = await user.isCorrectPassword(password);

        if (isPasswordCorrect) {
            const verificationCode = user.generateVerificationCode();
            await user.save();
            
            const emailSent = await sendVerificationCode(user.email, verificationCode);
            
            if (emailSent) {
                return res.json({ 
                    success: true, 
                    requireVerification: true,
                    message: 'Por favor verifica el código enviado a tu email'
                });
            } else {
                return res.status(500).json({ error: 'Error al enviar código de verificación' });
            }
        } else {
            return res.status(400).json({ error: 'USUARIO Y/O CONTRASEÑA INCORRECTA' });
        }
    } catch (err) {
        return res.status(500).json({ error: 'ERROR AL AUTENTICAR AL USUARIO' });
    }
});

app.post('/verify-2fa', async (req, res) => {
    const { username, code } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        if (user.verifyCode(code)) {
            const token = jwt.sign(
                { 
                    id: user._id, 
                    username: user.username,
                    role: user.role,
                    isVerified: true 
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            return res.json({ 
                success: true, 
                token,
                role: user.role,
                redirect: user.role === 'ADMIN' ? '/admin.html' : '/user.html'
            });
        } else {
            return res.status(400).json({ error: 'Código inválido o expirado' });
        }
    } catch (err) {
        console.error('Error detallado en la verificación:', err);
        return res.status(500).json({ error: 'Error en la verificación: ' + err.message });
    }
});

const protectRoute = (req, res, next) => {
    if (req.path === '/admin.html') {
        const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];
        
        if (!token) {
            return res.redirect('/index.html');
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role !== 'ADMIN') {
                return res.redirect('/user.html');
            }
        } catch (error) {
            return res.redirect('/index.html');
        }
    }
    next();
};

app.use(express.static(__dirname + '/public', { index: false }));
app.use(protectRoute);

// Rutas protegidas
app.get('/api/admin', verifyToken, checkRole(['ADMIN']), (req, res) => {
    res.json({ message: 'Bienvenido al panel de administración' });
});

app.get('/api/user', verifyToken, checkRole(['USER', 'ADMIN']), (req, res) => {
    res.json({ message: 'Bienvenido al panel de usuario' });
});


// Ruta para verificar la sesión
app.get('/api/verify-session', verifyToken, (req, res) => {
    try {
        res.json({
            success: true,
            role: req.user.role,
            username: req.user.username
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Sesión inválida' });
    }
});

// Actualiza la ruta de logout
app.post('/logout', verifyToken, (req, res) => {
    res.json({ success: true, redirect: '/index.html' });
});

app.listen(3000, () => {
    console.log('servidor listo...');
});
