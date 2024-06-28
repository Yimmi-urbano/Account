// middleware/validateEmail.js
const User = require('../models/User');

const validateEmail = async (req, res, next) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'Correo electrónico ya registrado' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Error al verificar el correo electrónico' });
  }
};

module.exports = validateEmail;
