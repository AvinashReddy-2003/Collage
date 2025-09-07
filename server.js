const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

require('dotenv').config();
// MongoDB connection using environment variable and direct connection string
mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 5000
})
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => {
        console.error("❌ MongoDB Connection Error:", err);
        process.exit(1);
    });

// Student Schema
const studentSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true }
});
const Student = mongoose.model('Student', studentSchema);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
// Serve static files from the public directory (where collage.html and dashboard.html are)
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Serve dashboard.html only via /dashboard route
app.get('/dashboard', (req, res) => {
    console.log("Serving dashboard.html");
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Login route: always redirect to /dashboard
app.post('/login', async (req, res) => {
    console.log("Received login request.");
    const { username, password } = req.body;
    if (!username || !password) {
        console.log("Login failed: Username or password missing.");
        return res.status(400).send("Username and password are required");
    }
    try {
        const student = await Student.findOne({ username });
        if (!student) {
            console.log(`Login failed: User '${username}' not found.`);
            return res.status(401).send("Invalid username or password");
        }
        const isMatch = await bcrypt.compare(password, student.password);
        if (!isMatch) {
            console.log("Login failed: Incorrect password.");
            return res.status(401).send("Invalid username or password");
        }
        console.log(`User '${username}' logged in successfully.`);
        // Always redirect to dashboard
        res.redirect('/dashboard');
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).send("Login Failed due to server error.");
    }
});

// Serve the collage.html at the root URL when the user accesses '/'
app.get('/', (req, res) => {
    console.log("Serving collage.html");
    res.sendFile(path.join(__dirname, 'public', 'collage.html'));
});

// In-memory store for OTPs (for demo; use DB for production)
const otpStore = {};

// Nodemailer transporter setup using environment variables
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
// Send OTP route (this must be inside your server.js, not at the top level)
app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = otp;
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER, // <-- FIXED
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP is: ${otp}`
        });
        res.json({ message: 'OTP sent!' });
    } catch (error) {
        console.error('Error sending OTP email:', error);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

// Verify OTP route
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (otpStore[email] && otpStore[email] === otp) {
        delete otpStore[email];
        return res.json({ success: true, message: 'OTP verified!' });
    }
    res.status(400).json({ success: false, message: 'Invalid OTP' });
});

// Register route (call this after OTP is verified)
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Username, password, and email are required' });
    }
    try {
        // Check if user already exists
        const existingUser = await Student.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ error: 'Username already exists' });
        }
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        // Save new user (FIX: include email)
        const newUser = new Student({ username, password: hashedPassword, email });
        await newUser.save();
        res.json({ message: 'Registration successful! You can now log in.' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed due to server error.' });
    }
});

// Start server and listen on the specified PORT
app.listen(PORT, () => {
    console.log(`Server running on http://127.0.0.1:${PORT}`);
});