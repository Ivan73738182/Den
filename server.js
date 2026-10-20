const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const users = {}; 
const tokens = {}; 
const posts = []; 

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, name: 'Den' });
});

app.post('/api/register', (req, res) => {
  let { name, username, password } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'Заполни все поля' });

  username = username.replace('@', '').toLowerCase();
  if (username.length < 5) return res.status(400).json({ error: 'Юз мин. 5 символов' });
  if (users[username]) return res.status(409).json({ error: 'Этот юз уже занят' });

  const token = makeToken();
  users[username] = { name, username, passwordHash: hashPassword(password) };
  tokens[token] = username;
  res.json({ ok: true, name, username, token });
});

app.post('/api/login', (req, res) => {
  let { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Нужны юз и пароль' });

  username = username.replace('@', '').toLowerCase();
  const user = users[username];
  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ error: 'Неверный юз или пароль' });
  }

  const token = makeToken();
  tokens[token] = username;
  res.json({ ok: true, name: user.name, username: user.username, token });
});

app.get('/api/posts', (req, res) => {
  res.json({ ok: true, posts: posts.reverse() }); 
});

app.post('/api/posts', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const username = tokens[token];

  if (!username) return res.status(401).json({ error: 'Не авторизован' });

  const { text } = req.body || {};
  if (!text || text.trim() === '') return res.status(400).json({ error: 'Текст пустой' });

  const post = {
    id: Date.now(),
    authorName: users[username].name,
    authorUsername: username,
    text: text,
    likes: [], 
    date: new Date().toISOString()
  };
  
  posts.push(post);
  res.json({ ok: true, post });
});

// Лайк поста
app.post('/api/posts/:id/like', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const username = tokens[token];
  if (!username) return res.status(401).json({ error: 'Не авторизован' });

  const postId = parseInt(req.params.id);
  const post = posts.find(p => p.id === postId);
  if (!post) return res.status(404).json({ error: 'Пост не найден' });

  const index = post.likes.indexOf(username);
  if (index === -1) {
    post.likes.push(username); 
  } else {
    post.likes.splice(index, 1); 
  }
  
  res.json({ ok: true, likes: post.likes });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Den сервер запущен на порту', PORT));
