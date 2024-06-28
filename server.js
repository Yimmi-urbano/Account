// server.js
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const User = require('./models/User');
const validateEmail = require('./middleware/validateEmail');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGODB_URI, {
  useUnifiedTopology: true,
});

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });
};

// Ruta de registro
app.post('/api/register', validateEmail, async (req, res) => {
  const { email, password, phonecell, condition, date_register, last_time } = req.body;
  try {
    const user = await User.create({
      email,
      password,
      phonecell,
      condition,
      date_register,
      last_time
    });
    res.status(201).json({
      _id: user._id,
      email: user.email,
      phonecell: user.phonecell,
      condition: user.condition,
      date_register: user.date_register,
      last_time: user.last_time,
      token: generateToken(user._id)
    });
  } catch (error) {
    res.status(400).json({ message: 'Error al registrar el usuario' });
  }
});

// Ruta de inicio de sesión
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }
    res.json({
      _id: user._id,
      email: user.email,
      phonecell: user.phonecell,
      condition: user.condition,
      date_register: user.date_register,
      last_time: user.last_time,
      token: generateToken(user._id)
    });
  } catch (error) {
    res.status(400).json({ message: 'Error al iniciar sesión' });
  }
});

// Ruta para validar token
app.post('/api/validate-token', (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ valid: true, userId: decoded.id });
  } catch (error) {
    res.status(401).json({ valid: false, message: 'Token inválido' });
  }
});

// Ruta para actualizar last_time
app.put('/api/update-last-time/:id', async (req, res) => {
  const { id } = req.params;
  const { last_time } = req.body;
  try {
    const user = await User.findByIdAndUpdate(id, { last_time }, { new: true });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json({
      _id: user._id,
      email: user.email,
      phonecell: user.phonecell,
      condition: user.condition,
      date_register: user.date_register,
      last_time: user.last_time
    });
  } catch (error) {
    res.status(400).json({ message: 'Error al actualizar el usuario' });
  }
});

// Ruta para actualizar condition
app.put('/api/update-condition/:id', async (req, res) => {
  const { id } = req.params;
  const { condition } = req.body;
  try {
    const user = await User.findByIdAndUpdate(id, { condition }, { new: true });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json({
      _id: user._id,
      email: user.email,
      phonecell: user.phonecell,
      condition: user.condition,
      date_register: user.date_register,
      last_time: user.last_time
    });
  } catch (error) {
    res.status(400).json({ message: 'Error al actualizar el usuario' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor de autenticación corriendo en el puerto ${PORT}`));
