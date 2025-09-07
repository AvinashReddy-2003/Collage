const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection
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
app.use(express.json());

// Serve static files from the public folder
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Root route: serve collage.html
app.get('/', (req, res) => {
    const filePath = path.join(publicPath, 'collage.html');
    console.log(`Serving: ${filePath}`);
    res.sendFile(filePath, (err) => {
        if (err) console.error('Error sending collage.html:', err);
    });
});

// Dashboard route
app.get('/dashboard', (req, res) => {
    const filePath = path.join(publicPath, 'dashboard.html');
    console.log(`Serving: ${filePath}`);
    res.sendFile(filePath, (err) => {
        if (err) console.error('Error sending dashboard.html:', err);
    });
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("Username and password required");
    try {
        const student = await Student.findOne({ username });
        if (!student) return res.status(401).send("Invalid username or password");

        const isMatch = await bcrypt.compare(password, student.password);
        if (!isMatch) return res.status(401).send("Invalid username or password");

        console.log(`User '${username}' logged in successfully.`);
        res.redirect('/dashboard');
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).send("Server error");
    }
});

// In-memory OTP store (for demo)
const otpStore = {};

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Send OTP route
app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = otp;

    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP is: ${otp}`
        });
        res.json({ message: 'OTP sent!' });
    } catch (error) {
        console.error('Error sending OTP:', error);
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

// Register route
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) return res.status(400).json({ error: 'All fields required' });

    try {
        const existingUser = await Student.findOne({ username });
        if (existingUser) return res.status(409).json({ error: 'Username already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new Student({ username, password: hashedPassword, email });
        await newUser.save();
        res.json({ message: 'Registration successful!' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port http://127.0.0.1:${PORT}`);
});
