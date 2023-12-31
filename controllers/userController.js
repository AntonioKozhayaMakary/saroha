const User = require('../models/userModel')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // Import the bcrypt library

const createUser = async (req, res) => {
  const { username, password, messages } = req.body;

  // Validation checks
  if (!isValidUsername(username) || !isValidPassword(password)) {
    return res.status(400).json({ error: "Invalid username or password." });
  }

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Convert the username to lowercase
    const lowercaseUsername = username.toLowerCase();

    // Attempt to add the new user to the database with the hashed password and lowercase username
    const user = await User.create({ username: lowercaseUsername, password: hashedPassword, messages });
    // Create a JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role }, // Payload
      process.env.JWT_SECRET, // Dynamic secret key
      { expiresIn: '1h' } // Token expiration time
    );


    // Send a success response with the user data and token
    res.status(200).json({ user: { username: user.username, role: user.role }, token });

  } catch (error) {
    if (error.code === 11000 && error.keyPattern.username) {
      res.status(409).json({ error: "Username is already in use." });
    } else {
      res.status(500).json({ error: "Internal server error. Please try again later." });
    }
  }
};

function isValidUsername(username) {
  const usernamePattern = /^[a-z0-9]{8,20}$/;
  return usernamePattern.test(username) && !/\s/.test(username);
}

function isValidPassword(password) {
  const passwordPattern = /^[a-zA-Z0-9]{8,15}$/;
  return passwordPattern.test(password) && !/\s/.test(password);
}

const getUserMessages = async (req, res) => {
  const { id } = req.params;

  var token = req.headers.authorization;


  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  var tokenParts = token.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(401).json({ error: "Invalid token format." });
  }
  token = tokenParts[1]; // Extracting just the token part

  if (typeof token !== 'string') {
    return res.status(401).json({ error: "Invalid type." });
  }

  try {

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded.userId || !decoded.username) {
      return res.status(401).json({ error: "Invalid token" });
    }
    // Assuming the token contains user information like userId
    const userIdFromToken = decoded.userId;

    if (id !== userIdFromToken) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const user = await User.findById(id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }




    // Get today's date
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Set hours, minutes, seconds, and milliseconds to 0 for comparison

    // Filter messages for today
    const todayMessages = user.messages.filter(message => {
      const messageDate = new Date(message.timestamp);
      messageDate.setHours(0, 0, 0, 0);

      return messageDate.getTime() === today.getTime();
    });

    // Extracting content of messages for today
    const todayMessageContent = todayMessages.map(message => message.content);

    res.status(200).json({ todayMessageContent });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


const loginUser = async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find the user by their username
    const user = await User.findOne({ username: username.toLowerCase() });

    // Check if the user exists
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    // Compare the provided password with the hashed password stored in the database
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    // Create a JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role }, // Payload
      process.env.JWT_SECRET, // Dynamic secret key
      { expiresIn: '1h' } // Token expiration time
    );


    // Send a success response with the user data and token
    res.status(200).json({ user: { username: user.username, role: user.role }, token });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: "Internal server error. Please try again later." });
  }
};



// Delete a user by ID
const deleteUser = async (req, res) => {

  var token = req.headers.authorization;


  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  var tokenParts = token.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(401).json({ error: "Invalid token format." });
  }
  token = tokenParts[1]; // Extracting just the token part

  if (typeof token !== 'string') {
    return res.status(401).json({ error: "Invalid type." });
  }

  try {

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded.userId || !decoded.username) {
      return res.status(401).json({ error: "Invalid token" });
    }
    // Assuming the token contains user information like userId
    const userIdFromToken = decoded.userId;

    const userId = req.params.id; // Assuming you receive the user's ID as a URL parameter

    if (userId !== userIdFromToken) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const user = await User.findByIdAndRemove(userId);

    if (user) {
      res.status(200).json({ message: 'User deleted successfully' });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


const updateUser = async (req, res) => {
  const { id } = req.params;
  var { username, password } = req.body; // Include username in the request body
  var token = req.headers.authorization;

  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  var tokenParts = token.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(401).json({ error: "Invalid token format." });
  }
  token = tokenParts[1]; // Extracting just the token part

  if (typeof token !== 'string') {
    return res.status(401).json({ error: "Invalid type." });
  }

  try {
    // Verify the token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    // Check if the decoded token contains a user ID
    if (!decodedToken.userId || !decodedToken.username) {
      return res.status(401).json({ error: "Invalid token" });
    }

    // Check if the user ID from the token matches the ID in the request parameters
    if (decodedToken.userId !== id) {
      return res.status(403).json({ error: 'Forbidden. You do not have permission to update this user.' });
    }

    // If password is provided, validate and hash it

    if (password) {
      if (!isValidPassword(password)) {
        return res.status(400).json({ error: 'Invalid password.' });
      }

      const saltRounds = 10;
      password = await bcrypt.hash(password, saltRounds);
    }

    // Validate other fields if needed
    // Example: if (messages && !isValidMessages(messages)) { ... }

    // Use findByIdAndUpdate to update the user
    const updateData = {
      ...(username && { username }), // Only update if username is provided
      ...(password && { password }),
    };

    const user = await User.findByIdAndUpdate(id, updateData, { new: true });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Unauthorized. Invalid token.' });
    }
    res.status(500).json({ error: error.message });
  }
};


const addMessageToUser = async (req, res) => {
  const { username } = req.params; // Assuming the username is used for identification
  const { messageContent } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.messages.push({ content: messageContent, timestamp: Date.now() });


    await user.save();
    res.status(200).json({ message: `Message added to ${username}'s messages.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


const search = async (req, res) => {
  var token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  var tokenParts = token.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(401).json({ error: "Invalid token format." });
  }
  token = tokenParts[1]; // Extracting just the token part

  if (typeof token !== 'string') {
    return res.status(401).json({ error: "Invalid type." });
  }

  let { username, page } = req.params; // Get the username and page number from query parameters
  page = parseInt(page) || 1; // Convert page to a number; default to 1 if not provided

  if (!username) {
    return res.status(400).json({ message: 'Please provide a username to search' });
  }

  const perPage = 10; // Number of users per page
  const startIndex = (page - 1) * perPage;

  // Case-insensitive search by creating a regex pattern with the provided username
  const regex = new RegExp(username, 'i');
  console.log('Regex Pattern:', regex);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded.userId || !decoded.username) {
      return res.status(401).json({ error: "Invalid token" });
    }

    const foundUsers = await User.find({ username: { $regex: regex } })
      .skip(startIndex)
      .limit(perPage + 1); // Fetch one more than perPage to check if there are more results

    const users = foundUsers.slice(0, perPage); // Get only the required number of users for the current page

    const hasMore = foundUsers.length > perPage; // Check if there are more results

    if (users.length === 0) {
      return res.status(404).json({ message: 'No users found with a similar username' });
    }

    return res.status(200).json({ users, hasMore });
  } catch (err) {
    return res.status(500).json({ message: 'ntek', error: err.message });
  }
};


const verifyToken = async (req, res) => {
  let token = req.headers.authorization; // Accessing the token from the Authorization header

 

  if (!token) {
    return res.status(401).json({ error: "Access denied. Token is required." });
  }

  // The token might have the format "Bearer <actual_token>". You may need to extract just the token.
  let tokenParts = token.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(401).json({ error: "Invalid token format." });
  }
  token = tokenParts[1]; // Extracting just the token part

  if (typeof token !== 'string') {
    return res.status(401).json({ error: "Invalid type." });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(decoded);
    // Check if the token payload contains required fields or any other validation logic
    if (!decoded.userId || !decoded.username) {
      return res.status(401).json({ error: "Invalid token" });
    }

    return res.status(200).json({ username: decoded.username });
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({ error: "Invalid token." });
  }
};



module.exports = {
  updateUser,
  deleteUser,
  createUser,
  getUserMessages,
  loginUser,
  addMessageToUser,
  search,
  verifyToken
}