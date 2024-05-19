const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../model/user");
const router = express.Router();
const bcrypt = require('bcryptjs');

// Signup route
router.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10); // Hash the password
    const user = new User({ username, password: hashedPassword }); // Save the hashed password
    await user.save();
    res.status(201).json({ message: "New user registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// Login route
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ message: "Invalid username " });
    }

    // Compare the provided password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' } // Optional: set token expiration time
    );
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

module.exports = router;


