const mongoose = require("mongoose");

// Defining a Task Schema
const TaskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  duedate: { type: Date, required: true },
  status: { type: String, required: true },
  assignedtouser: { type: String, required: true },
  assigneduserid: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
}, { timestamps: true });

module.exports = mongoose.model('Tasks', TaskSchema);