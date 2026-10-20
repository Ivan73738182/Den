// ============================================================
//  Den — сервер соцсети
//  Шаг 1: регистрация и вход (хранение в памяти)
// ============================================================

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ---------- Хранилище (в памяти, при перезапуске сбрасывается) ----------
const users = {};      // username -> { username, passwordHash, token }
const tokens = {};     // token -> username

// ---------- Утилиты ----------
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

// ---------- Проверка, что сервер жив ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, name: 'Den', time: new Date().toISOString() });
});

// ---------- Регистрация ----------
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Нужны username и password' });
  }
  if (username.length < 3) {
    return res.status(400).json({ error: 'Имя слишком короткое (мин. 3)' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Пароль слишком короткий (мин. 4)' });
  }
  if (users[username]) {
    return res.status(409).json({ error: 'Такое имя уже занято' });
  }

  const token = makeToken();
  users[username] = {
    username,
    passwordHash: hashPassword(password),
    token
  };
  tokens[token] = username;

  console.log('Регистрация:', username);
  res.json({ ok: true, username, token });
});

// ---------- Вход ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Нужны username и password' });
  }

  const user = users[username];
  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ error: 'Неверное имя или пароль' });
  }

  // Новый токен при каждом входе
  const token = makeToken();
  user.token = token;
  tokens[token] = username;

  console.log('Вход:', username);
  res.json({ ok: true, username, token });
});

// ---------- Проверка токена (пригодится дальше) ----------
app.get('/api/me', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const username = tokens[token];

  if (!username) {
    return res.status(401).json({ error: 'Неверный токен' });
  }
  res.json({ ok: true, username });
});

// ---------- Запуск ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Den сервер запущен на порту', PORT);
});
