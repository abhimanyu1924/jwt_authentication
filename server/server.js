const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const app = express();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
app.use(bodyParser.json());
app.use(cors());


const users = []; // In-memory store for users

// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}
// Session configuration
app.use(session({
  secret: 'd8544944a063a41dbecc5be7569f725eb7ddfe301ffc4250298ef3ca1086aca7c21ceeeb71c9a42ee6f72c301fabae61b5b42dcd419a58ee8e05b8ebcf89c06d',
  resave: false,
  saveUninitialized: true
}));

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
  clientID: '1076232446966-5itqovsm7vaufdn1qkqc59i1hb24266l.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: 'http://localhost:3000/auth/google/callback'
},
  function(accessToken, refreshToken, profile, done) {
    // Here, you can create or find the user in your database
    // and associate the Google profile with the user
    // For simplicity, we'll just return the profile
    return done(null, profile);
  }
));
passport.serializeUser(function(user, done) {
    done(null, user);
  });
  
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });
  app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));
  
  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    function(req, res) {
      // Successful authentication, redirect to the index page
      res.redirect('/home.html');
    });
// Routes
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Logic for user authentication
    // For example:
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(400).json({ error: 'Invalid username or password' });

    const token = jwt.sign({ username: user.username }, 'your-secret-key', { expiresIn: '1h' });
    res.json({ token });
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    // Logic for user registration
    if (users.find(u => u.username === username)) return res.status(400).json({ errors: [{ msg: 'Username already exists' }] });
    users.push({ username, password });
    res.status(201).json({ message: 'User registered successfully' });
});

app.get('/home', authenticateToken, (req, res) => {
    res.json({ username: req.user.username });
});

app.get('/admin', authenticateToken, (req, res) => {
    // Only allow admin user
    if (req.user.username !== 'admin') return res.sendStatus(403);
    res.json({ username: req.user.username });
});

// Start server
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
