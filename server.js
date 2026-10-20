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
  let { name, username, password } = req.body || {};

  if (!name || !username || !password) {
    return res.status(400).json({ error: 'Заполни все поля' });
  }

  username = username.replace('@', '').toLowerCase();

  if (name.length < 2) {
    return res.status(400).json({ error: 'Имя слишком короткое (мин. 2)' });
  }
  if (username.length < 5) {
    return res.status(400).json({ error: 'Юз должен быть не менее 5 символов' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Пароль слишком короткий (мин. 4)' });
  }
  if (users[username]) {
    return res.status(409).json({ error: 'Этот юз уже занят. Придумай другой.' });
  }

  const token = makeToken();
  users[username] = {
    name,
    username,
    passwordHash: hashPassword(password),
    token
  };
  tokens[token] = username;

  console.log('Регистрация:', username, '(', name, ')');
  res.json({ ok: true, name, username, token });
});

app.post('/api/login', (req, res) => {
  let { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Нужны юз и пароль' });
  }

  username = username.replace('@', '').toLowerCase();

  const user = users[username];
  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ error: 'Неверный юз или пароль' });
  }

  const token = makeToken();
  user.token = token;
  tokens[token] = username;

  console.log('Вход:', username);
  res.json({ ok: true, name: user.name, username: user.username, token });
});

app.get('/api/me', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const username = tokens[token];

  if (!username) {
    return res.status(401).json({ error: 'Неверный токен' });
  }
  const user = users[username];
  res.json({ ok: true, name: user.name, username: user.username });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Den сервер запущен на порту', PORT);
});
