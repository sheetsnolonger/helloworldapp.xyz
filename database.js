const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const databasePath = process.env.DATABASE_PATH || "./data/helloworld.db";
const resolvedPath = path.resolve(databasePath);

fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });

const db = new Database(resolvedPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

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
        foreign key(user_id) references users(id) on delete cascade
    );

    create table if not exists likes (
        id integer primary key autoincrement,
        user_id integer not null,
        post_id integer not null,
        unique(user_id, post_id),
        foreign key(user_id) references users(id) on delete cascade,
        foreign key(post_id) references posts(id) on delete cascade
    );

    create table if not exists comments (
        id integer primary key autoincrement,
        user_id integer not null,
        post_id integer not null,
        content text not null,
        created_at datetime default current_timestamp,
        foreign key(user_id) references users(id) on delete cascade,
        foreign key(post_id) references posts(id) on delete cascade
    );

    create table if not exists follows (
        id integer primary key autoincrement,
        follower_id integer not null,
        following_id integer not null,
        unique(follower_id, following_id),
        foreign key(follower_id) references users(id) on delete cascade,
        foreign key(following_id) references users(id) on delete cascade
    );

    create index if not exists idx_posts_user_created
        on posts(user_id, created_at desc);

    create index if not exists idx_likes_post
        on likes(post_id);

    create index if not exists idx_comments_post
        on comments(post_id);
`);

module.exports = db;