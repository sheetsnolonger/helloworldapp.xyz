const sqlite = require("better-sqlite3");

const db = new sqlite("hello.db");

db.pragma("journal_mode = wal");

db.exec(`
    create table if not exists users (
        id integer primary key autoincrement,
        username text unique not null,
        password text not null,
        bio text default '',
        created_at datetime default current_timestamp
    );

    create table if not exists posts (
        id integer primary key autoincrement,
        user_id integer not null,
        content text not null,
        created_at datetime default current_timestamp,
        foreign key(user_id) references users(id)
    );

    create table if not exists likes (
        id integer primary key autoincrement,
        user_id integer not null,
        post_id integer not null,
        unique(user_id, post_id)
    );

    create table if not exists comments (
        id integer primary key autoincrement,
        user_id integer not null,
        post_id integer not null,
        content text not null,
        created_at datetime default current_timestamp
    );

    create table if not exists follows (
        id integer primary key autoincrement,
        follower_id integer not null,
        following_id integer not null,
        unique(follower_id, following_id)
    );
`);

module.exports = db;