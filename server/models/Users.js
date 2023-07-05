const mongoose = require('mongoose');

//Defining a user schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  photo: {
    type: String
  },
  password: { type: String, required: true }
}, { timestamps: true });

module.exports = mongoose.model('Users', UserSchema);
