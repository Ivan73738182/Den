const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const users = {}; 
const tokens = {}; 

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, name: 'Den', time: new Date().toISOString() });
});

app.post('/api/register', (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Нужны email и password' });
  }
  if (!email.includes('@')) {
    return res.status(400).json({ error: 'Неверный формат почты' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Пароль слишком короткий (мин. 4)' });
  }
  if (users[email]) {
    return res.status(409).json({ error: 'Эта почта уже занята' });
  }

  const token = makeToken();
  users[email] = {
    email,
    passwordHash: hashPassword(password),
    token
  };
  tokens[token] = email;

  console.log('Регистрация:', email);
  res.json({ ok: true, email, token });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Нужны email и password' });
  }

  const user = users[email];
  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ error: 'Неверная почта или пароль' });
  }

  const token = makeToken();
  user.token = token;
  tokens[token] = email;

  console.log('Вход:', email);
  res.json({ ok: true, email, token });
});

app.get('/api/me', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const email = tokens[token];

  if (!email) {
    return res.status(401).json({ error: 'Неверный токен' });
  }
  res.json({ ok: true, email });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Den сервер запущен на порту', PORT);
});
