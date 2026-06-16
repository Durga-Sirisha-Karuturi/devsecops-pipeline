const express = require('express');
const morgan  = require('morgan');
const app     = express();

app.use(express.json());
app.use(morgan('combined'));

// INTENTIONAL VULNERABILITY #1: hardcoded secret (TruffleHog will catch this)
const DB_PASSWORD = "superSecret123!";
const JWT_SECRET  = "my-hardcoded-jwt-secret-key-1234";

// INTENTIONAL VULNERABILITY #2: eval injection (SonarQube SAST will flag this)
app.post('/calculate', (req, res) => {
  const { expression } = req.body;
  try {
    // eval is dangerous — arbitrary code execution risk
    const result = eval(expression);
    res.json({ result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// INTENTIONAL VULNERABILITY #3: no input validation / SQL injection demo
app.get('/search', (req, res) => {
  const { query } = req.query;
  // Simulating unsanitised DB query (no parameterisation)
  const fakeQuery = `SELECT * FROM users WHERE name = '${query}'`;
  res.json({ query: fakeQuery, note: "SQL injection demo" });
});

// Healthy endpoint for liveness probe
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: process.env.APP_VERSION || '1.0.0' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`App running on port ${PORT}`));

module.exports = app;
