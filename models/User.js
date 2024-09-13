// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const ConditionSchema = new mongoose.Schema({
  status: { type: String, required: true },
  msg: { type: String, required: true }
});

const ComponentsSchema = new mongoose.Schema({
   name_component: { type: String, required: true },
   status: { type: String, required: true }
});


const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phonecell: { type: String, required: true },
  condition: { type: ConditionSchema, required: false },
  components: { type: [ComponentsSchema], required: false },
  date_register: { type: String, required: false },
  last_time: { type: String, required: false }
});

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.matchPassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', UserSchema);
