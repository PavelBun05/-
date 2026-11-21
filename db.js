const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "music.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    displayName TEXT NOT NULL,
    salt TEXT NOT NULL,
    passwordHash TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS user_favorites (
    userId TEXT NOT NULL,
    trackId TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    PRIMARY KEY (userId, trackId)
  );

  CREATE TABLE IF NOT EXISTS friends (
    userId TEXT NOT NULL,
    friendId TEXT NOT NULL,
    PRIMARY KEY (userId, friendId)
  );

  CREATE TABLE IF NOT EXISTS albums (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL,
    ownerId TEXT NOT NULL,
    ownerName TEXT NOT NULL,
    sharedWith TEXT NOT NULL,
    sharedWithName TEXT NOT NULL,
    tracks TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );
`);

module.exports = db;
