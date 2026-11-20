const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SECRET_FILE = path.join(DATA_DIR, '.token-secret');
const USER_DATA_FILE = path.join(DATA_DIR, 'user-data.json');
const FRIENDS_FILE = path.join(DATA_DIR, 'friends.json');
const ALBUMS_FILE = path.join(DATA_DIR, 'albums.json');
const MUSIC_DIR = path.join(__dirname, 'public', 'music');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(MUSIC_DIR, { recursive: true });
for (const [file, initial] of [[USERS_FILE, []], [USER_DATA_FILE, {}], [FRIENDS_FILE, {}], [ALBUMS_FILE, []]]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(initial, null, 2));
}
if (!fs.existsSync(SECRET_FILE)) fs.writeFileSync(SECRET_FILE, crypto.randomBytes(48).toString('hex'));
const TOKEN_SECRET = fs.readFileSync(SECRET_FILE, 'utf8');
const readJson = (file, fallback) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } };
const writeJson = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2), 'utf8');
const readUsers = () => readJson(USERS_FILE, []);
const readUserData = () => readJson(USER_DATA_FILE, {});
const readFriends = () => readJson(FRIENDS_FILE, {});
const readAlbums = () => readJson(ALBUMS_FILE, []);
const cleanUser = user => ({ id: user.id, username: user.username, displayName: user.displayName });

function makeToken(user) {
  const payload = Buffer.from(JSON.stringify({ id: user.id, exp: Date.now() + 30 * 86400000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}
function verifyToken(token) {
  if (typeof token !== 'string') return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest();
  let actual;
  try { actual = Buffer.from(signature, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.id || data.exp < Date.now()) return null;
    return readUsers().find(u => u.id === data.id) || null;
  } catch { return null; }
}
function authUser(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const user = verifyToken(token);
  if (!user) return res.status(401).json({ error: 'Сначала войдите в аккаунт' });
  req.user = user;
  next();
}
function validUsername(value) { return /^[a-zA-Zа-яА-ЯёЁ0-9_.-]{3,20}$/.test(value); }
function getFavorites(userId) { return (readUserData()[userId] || { favorites: [] }).favorites || []; }
function setFavorites(userId, favorites) {
  const data = readUserData();
  data[userId] = data[userId] || {};
  data[userId].favorites = favorites;
  writeJson(USER_DATA_FILE, data);
}
function getMusicCatalog() {
  const allowed = new Set(['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac']);
  return fs.readdirSync(MUSIC_DIR, { withFileTypes: true })
    .filter(entry => entry.isFile() && allowed.has(path.extname(entry.name).toLowerCase()))
    .sort((a, b) => a.name.localeCompare(b.name, 'ru', { numeric: true }))
    .map(entry => {
      const file = entry.name;
      const title = path.basename(file, path.extname(file)).replace(/[._]+/g, ' ').replace(/\s+/g, ' ').trim();
      return { id: file, title: title || file, url: `/music/${encodeURIComponent(file)}` };
    });
}

app.post('/api/register', (req, res) => {
  const username = String(req.body.username || '').trim();
  const displayName = String(req.body.displayName || '').trim().slice(0, 24);
  const password = String(req.body.password || '');
  if (!validUsername(username)) return res.status(400).json({ error: 'Логин: 3–20 символов, буквы, цифры, точка, дефис или _' });
  if (displayName.length < 2) return res.status(400).json({ error: 'Укажи имя длиной не менее 2 символов' });
  if (password.length < 6 || password.length > 100) return res.status(400).json({ error: 'Пароль должен содержать от 6 до 100 символов' });
  const users = readUsers();
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Такой логин уже занят' });
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto.scryptSync(password, salt, 64).toString('hex');
  const user = { id: crypto.randomUUID(), username, displayName, salt, passwordHash, createdAt: new Date().toISOString() };
  users.push(user); writeJson(USERS_FILE, users);
  res.status(201).json({ token: makeToken(user), user: cleanUser(user) });
});
app.post('/api/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = readUsers().find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });
  const hash = crypto.scryptSync(password, user.salt, 64);
  const saved = Buffer.from(user.passwordHash, 'hex');
  if (hash.length !== saved.length || !crypto.timingSafeEqual(hash, saved)) return res.status(401).json({ error: 'Неверный логин или пароль' });
  res.json({ token: makeToken(user), user: cleanUser(user) });
});
app.get('/api/me', authUser, (req, res) => res.json({ user: cleanUser(req.user) }));
app.get('/api/music', authUser, (req, res) => res.json({ tracks: getMusicCatalog() }));
app.get('/api/me/favorites', authUser, (req, res) => res.json({ tracks: getFavorites(req.user.id) }));
app.put('/api/me/favorites', authUser, (req, res) => {
  const track = req.body.track;
  if (!track || typeof track.id !== 'string' || typeof track.title !== 'string' || typeof track.url !== 'string') return res.status(400).json({ error: 'Некорректный трек' });
  const catalog = getMusicCatalog();
  if (!catalog.some(t => t.id === track.id)) return res.status(404).json({ error: 'Этого файла больше нет на сервере' });
  let favorites = getFavorites(req.user.id);
  if (req.body.action === 'remove') favorites = favorites.filter(t => t.id !== track.id);
  else if (!favorites.some(t => t.id === track.id)) favorites.push(catalog.find(t => t.id === track.id));
  setFavorites(req.user.id, favorites);
  res.json({ tracks: favorites });
});
app.get('/api/friends', authUser, (req, res) => {
  const ids = readFriends()[req.user.id] || [];
  const users = readUsers();
  res.json({ friends: ids.map(id => users.find(u => u.id === id)).filter(Boolean).map(cleanUser) });
});
app.post('/api/friends', authUser, (req, res) => {
  const username = String(req.body.username || '').trim();
  const target = readUsers().find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!target) return res.status(404).json({ error: 'Пользователь с таким логином не найден' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'Нельзя добавить самого себя' });
  const friends = readFriends();
  friends[req.user.id] = friends[req.user.id] || [];
  friends[target.id] = friends[target.id] || [];
  if (!friends[req.user.id].includes(target.id)) friends[req.user.id].push(target.id);
  if (!friends[target.id].includes(req.user.id)) friends[target.id].push(req.user.id);
  writeJson(FRIENDS_FILE, friends);
  res.status(201).json({ friend: cleanUser(target), friends: friends[req.user.id].map(id => cleanUser(readUsers().find(u => u.id === id))).filter(Boolean) });
});
app.get('/api/users/:id/favorites', authUser, (req, res) => {
  // Избранное доступно для просмотра участникам сервиса, чтобы можно было открыть музыку соседа по комнате.
  const user = readUsers().find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ user: cleanUser(user), tracks: getFavorites(user.id) });
});
app.get('/api/albums', authUser, (req, res) => {
  const albums = readAlbums().filter(a => a.ownerId === req.user.id || a.sharedWith === req.user.id);
  res.json({ albums });
});
app.post('/api/albums', authUser, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 50);
  const friendId = String(req.body.friendId || '');
  const mode = String(req.body.mode || 'union');
  if (name.length < 2) return res.status(400).json({ error: 'Название должно содержать минимум 2 символа' });
  if (!['union', 'common', 'friend'].includes(mode)) return res.status(400).json({ error: 'Неизвестный тип альбома' });
  const friendIds = readFriends()[req.user.id] || [];
  if (!friendIds.includes(friendId)) return res.status(403).json({ error: 'Выбери пользователя из списка друзей' });
  const users = readUsers();
  const friend = users.find(u => u.id === friendId);
  if (!friend) return res.status(404).json({ error: 'Друг не найден' });
  const mine = getFavorites(req.user.id);
  const theirs = getFavorites(friendId);
  const mineMap = new Map(mine.map(t => [t.id, t]));
  const theirMap = new Map(theirs.map(t => [t.id, t]));
  let tracks;
  if (mode === 'common') tracks = mine.filter(t => theirMap.has(t.id));
  else if (mode === 'friend') tracks = theirs;
  else tracks = [...mine, ...theirs.filter(t => !mineMap.has(t.id))];
  const album = { id: crypto.randomUUID(), name, mode, ownerId: req.user.id, ownerName: req.user.displayName, sharedWith: friendId, sharedWithName: friend.displayName, tracks, createdAt: new Date().toISOString() };
  const albums = readAlbums(); albums.unshift(album); writeJson(ALBUMS_FILE, albums);
  res.status(201).json({ album });
});
app.delete('/api/albums/:id', authUser, (req, res) => {
  const albums = readAlbums();
  const album = albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Альбом не найден' });
  if (album.ownerId !== req.user.id) return res.status(403).json({ error: 'Удалить альбом может только его создатель' });
  writeJson(ALBUMS_FILE, albums.filter(a => a.id !== album.id));
  res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const rooms = new Map();
function createRoom(code) { return { code, adminId: null, users: new Map(), queue: [], current: null, isPlaying: false, positionAtSync: 0, syncedAt: Date.now() }; }
function roomState(room) { return { code: room.code, adminId: room.adminId, users: [...room.users.values()], queue: room.queue, current: room.current, isPlaying: room.isPlaying, positionAtSync: room.positionAtSync, syncedAt: room.syncedAt, serverTime: Date.now() }; }
function send(ws, data) { if (ws.readyState === 1) ws.send(JSON.stringify(data)); }
function broadcast(room, data) { const payload = JSON.stringify(data); for (const ws of room.users.keys()) if (ws.readyState === 1) ws.send(payload); }
function updatePosition(room) { if (!room.isPlaying || !room.current) return; room.positionAtSync += (Date.now() - room.syncedAt) / 1000; room.syncedAt = Date.now(); }
function nextTrack(room) { room.current = room.queue.shift() || null; room.isPlaying = Boolean(room.current); room.positionAtSync = 0; room.syncedAt = Date.now(); }
wss.on('connection', ws => {
  ws.userId = null; ws.room = null;
  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }
    if (msg.type === 'join') {
      const user = verifyToken(msg.token);
      if (!user) { send(ws, { type: 'auth:error', message: 'Сессия завершена. Войди в аккаунт заново.' }); ws.close(); return; }
      const code = String(msg.room || '').trim().toUpperCase().slice(0, 12); if (!code) return;
      if (ws.room) ws.room.users.delete(ws);
      if (!rooms.has(code)) rooms.set(code, createRoom(code));
      const room = rooms.get(code); ws.room = room; ws.userId = user.id; ws.nick = user.displayName;
      room.users.set(ws, { id: user.id, nick: user.displayName });
      if (!room.adminId) room.adminId = user.id;
      send(ws, { type: 'welcome', you: user.id, state: roomState(room) });
      broadcast(room, { type: 'users', users: [...room.users.values()], adminId: room.adminId }); return;
    }
    const room = ws.room; if (!room) return;
    switch (msg.type) {
      case 'play': if (ws.userId !== room.adminId || !room.current) return; updatePosition(room); room.isPlaying = true; room.syncedAt = Date.now(); broadcast(room, { type: 'sync', state: roomState(room) }); break;
      case 'pause': if (ws.userId !== room.adminId) return; updatePosition(room); room.isPlaying = false; broadcast(room, { type: 'sync', state: roomState(room) }); break;
      case 'seek': if (ws.userId !== room.adminId) return; room.positionAtSync = Math.max(0, Number(msg.position) || 0); room.syncedAt = Date.now(); broadcast(room, { type: 'sync', state: roomState(room) }); break;
      case 'queue:add': {
        const track = getMusicCatalog().find(t => t.id === msg.trackId);
        const url = track ? track.url : String(msg.url || '').trim();
        if (!url) return;
        room.queue.push({ id: crypto.randomUUID(), title: String(track ? track.title : msg.title || 'Без названия').slice(0, 100), url, addedBy: ws.nick });
        if (!room.current) nextTrack(room);
        broadcast(room, { type: 'sync', state: roomState(room) }); break;
      }
      case 'queue:remove': if (ws.userId !== room.adminId) return; room.queue = room.queue.filter(t => t.id !== msg.id); broadcast(room, { type: 'sync', state: roomState(room) }); break;
      case 'next': if (ws.userId !== room.adminId) return; nextTrack(room); broadcast(room, { type: 'sync', state: roomState(room) }); break;
      case 'track:ended': if (ws.userId !== room.adminId || !room.current) return; nextTrack(room); broadcast(room, { type: 'sync', state: roomState(room) }); break;
    }
  });
  ws.on('close', () => {
    const room = ws.room; if (!room) return; room.users.delete(ws);
    if (ws.userId === room.adminId) { const nextSocket = room.users.keys().next().value; room.adminId = nextSocket ? nextSocket.userId : null; }
    broadcast(room, { type: 'users', users: [...room.users.values()], adminId: room.adminId });
    if (room.users.size === 0) rooms.delete(room.code);
  });
});
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Sync Music запущен: http://localhost:${PORT}`));
