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
  let { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Нужны имя и пароль' });
  }

  // Убираем @, если пользователь его ввел
  username = username.replace('@', '').toLowerCase();

  if (username.length < 5) {
    return res.status(400).json({ error: 'Имя должно быть не менее 5 символов' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Пароль слишком короткий (мин. 4)' });
  }
  if (users[username]) {
    return res.status(409).json({ error: 'Это имя уже занято. Придумай другое.' });
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

app.post('/api/login', (req, res) => {
  let { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Нужны имя и пароль' });
  }

  username = username.replace('@', '').toLowerCase();

  const user = users[username];
  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ error: 'Неверное имя или пароль' });
  }

  const token = makeToken();
  user.token = token;
  tokens[token] = username;

  console.log('Вход:', username);
  res.json({ ok: true, username, token });
});

app.get('/api/me', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const username = tokens[token];

  if (!username) {
    return res.status(401).json({ error: 'Неверный токен' });
  }
  res.json({ ok: true, username });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Den сервер запущен на порту', PORT);
});
