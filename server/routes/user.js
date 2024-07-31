// Could you provide the code snipper from 'user.js' that handles user sign-up using express router, including validation for username and password length, bcrypt for password hashing, JWT for handling JWT and integration with a user database stored in ../database.
const router = require('express').Router();
const { check, validationResult } = require('express-validator');

const bcrypt = require('bcrypt');
const JWT = require('jsonwebtoken');
const { users } = require('../database');

require('dotenv').config();

// Sign up
router.post(
  '/signup',
  [
    check('email', 'Invalid email').isEmail(),
    check('password', 'Password must be at least 6 chars long').isLength({ min: 6 }),
  ],
  async (req, res) => {
    const { email, password } = req.body;

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }

    let user = users.find((user) => user.email === email);

    if (user) {
      return res.status(200).json({
        errors: [
          {
            email: user.email,
            msg: 'The user already exists',
          },
        ],
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    users.push({
      email,
      password: hashedPassword,
    });

    const accessToken = await JWT.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1m' });

    res.json({ accessToken });
  }
);

// Log in
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  let user = users.find((user) => user.email === email);

  if (!user) {
    return res.status(400).json({
      errors: [{ msg: 'Invalid credentials' }],
    });
  }

  let isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({
      errors: [{ msg: 'Email or password is invalid' }],
    });
  }

  const accessToken = await JWT.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1m' });
  const refreshToken = await JWT.sign({ email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '5m' });

  refreshTokens.push(refreshToken);

  res.json({ accessToken, refreshToken });
});

let refreshTokens = [];

// Create new access token from refresh token
router.post('/token', async (req, res) => {
  const refreshToken = req.header('x-auth-token');

  if (!refreshToken) {
    res.status(401).json({
      errors: [{ msg: 'Token not found' }],
    });
  }

  if (!refreshTokens.includes(refreshToken)) {
    res.status(403).json({
      errors: [{ msg: 'Invalid refresh token' }],
    });
  }

  try {
    const user = await JWT.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const { email } = user;
    const accessToken = await JWT.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1m' });
    res.json({ accessToken });
  } catch (error) {
    res.status(403).json({
      errors: [{ msg: 'Invalid token' }],
    });
  }
});

// Deauthenticate - log out
router.delete('/logout', (req, res) => {
  const refreshToken = req.header('x-auth-token');
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.sendStatus(204);
});

module.exports = router;






 