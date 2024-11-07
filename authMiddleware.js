const jwt = require('jsonwebtoken');
const JWT_SECRET = 'tu_clave_secreta_muy_segura'; // En producción, usa variables de entorno

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1] || req.cookies?.token;

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

const checkRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Usuario no autenticado' });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Acceso denegado' });
        }

        next();
    };
};

module.exports = { verifyToken, checkRole, JWT_SECRET };