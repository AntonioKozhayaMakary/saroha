const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const userSchema = new Schema({
  username: {
    type: String,
    required: true,
    unique: true // Ensures that the username is unique
  },
  password: {
    type: String,
    required: true
  },
  messages: [
    {
      content: {
        type: String,
        required: true
      },
      timestamp: {
        type:Date,
        default: Date.now
      }
    }
  ]
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
