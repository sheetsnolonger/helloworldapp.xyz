const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const db = require("./database");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" }
}));
app.use(express.static("public"));

function requireLogin(req, res, next) {
    if (!req.session.userId) return res.redirect("/login");
    next();
}

function currentUser(req) {
    if (!req.session.userId) return null;
    return db.prepare("select id, username, bio from users where id = ?").get(req.session.userId);
}

app.locals.formatDate = date => new Date(date).toLocaleString().toLowerCase();

app.get("/", (req, res) => {
    if (req.session.userId) return res.redirect("/feed");
    res.render("index");
});

app.get("/register", (req, res) => res.render("register", { error: null }));

app.post("/register", async (req, res) => {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (username.length < 3) {
        return res.render("register", { error: "your username needs at least 3 characters." });
    }

    if (password.length < 6) {
        return res.render("register", { error: "your password needs at least 6 characters." });
    }

    if (db.prepare("select id from users where username = ?").get(username)) {
        return res.render("register", { error: "that username is already taken." });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(
        "insert into users (username, password) values (?, ?)"
    ).run(username, hash);

    req.session.userId = result.lastInsertRowid;
    res.redirect("/feed");
});

app.get("/login", (req, res) => res.render("login", { error: null }));

app.post("/login", async (req, res) => {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = db.prepare("select * from users where username = ?").get(username);

    if (!user) return res.render("login", { error: "we couldn't find that account." });

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) return res.render("login", { error: "that password isn't correct." });

    req.session.userId = user.id;
    res.redirect("/feed");
});

app.post("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/"));
});

app.get("/feed", requireLogin, (req, res) => {
    const user = currentUser(req);

    const posts = db.prepare(`
        select
            posts.*,
            users.username,
            (select count(*) from likes where likes.post_id = posts.id) as likes,
            (select count(*) from comments where comments.post_id = posts.id) as comments,
            exists(
                select 1 from likes
                where likes.post_id = posts.id
                and likes.user_id = ?
            ) as liked
        from posts
        join users on users.id = posts.user_id
        where posts.user_id = ?
        or posts.user_id in (
            select following_id from follows where follower_id = ?
        )
        order by posts.created_at desc
        limit 100
    `).all(user.id, user.id, user.id);

    res.render("feed", { user, posts });
});

app.post("/posts", requireLogin, (req, res) => {
    const content = String(req.body.content || "").trim();

    if (!content || content.length > 500) return res.redirect("/feed");

    db.prepare(
        "insert into posts (user_id, content) values (?, ?)"
    ).run(req.session.userId, content);

    res.redirect("/feed");
});

app.post("/posts/:id/like", requireLogin, (req, res) => {
    const postId = Number(req.params.id);

    const existing = db.prepare(
        "select id from likes where user_id = ? and post_id = ?"
    ).get(req.session.userId, postId);

    if (existing) {
        db.prepare("delete from likes where id = ?").run(existing.id);
    } else {
        db.prepare(
            "insert or ignore into likes (user_id, post_id) values (?, ?)"
        ).run(req.session.userId, postId);
    }

    res.redirect(req.get("referer") || "/feed");
});

app.post("/posts/:id/comments", requireLogin, (req, res) => {
    const postId = Number(req.params.id);
    const content = String(req.body.content || "").trim();

    if (!content || content.length > 300) {
        return res.redirect(req.get("referer") || "/feed");
    }

    db.prepare(
        "insert into comments (user_id, post_id, content) values (?, ?, ?)"
    ).run(req.session.userId, postId, content);

    res.redirect(req.get("referer") || "/feed");
});

app.get("/u/:username", requireLogin, (req, res) => {
    const username = String(req.params.username).toLowerCase();

    const user = db.prepare(
        "select id, username, bio, created_at from users where username = ?"
    ).get(username);

    if (!user) return res.status(404).send("user not found.");

    const posts = db.prepare(`
        select posts.*,
        (select count(*) from likes where likes.post_id = posts.id) as likes
        from posts
        where posts.user_id = ?
        order by posts.created_at desc
    `).all(user.id);

    const followers = db.prepare(
        "select count(*) as count from follows where following_id = ?"
    ).get(user.id).count;

    const following = db.prepare(
        "select count(*) as count from follows where follower_id = ?"
    ).get(user.id).count;

    const isFollowing = user.id !== req.session.userId &&
        !!db.prepare(
            "select id from follows where follower_id = ? and following_id = ?"
        ).get(req.session.userId, user.id);

    res.render("profile", {
        user,
        posts,
        followers,
        following,
        isFollowing,
        currentUser: currentUser(req)
    });
});

app.post("/u/:username/follow", requireLogin, (req, res) => {
    const username = String(req.params.username).toLowerCase();

    const target = db.prepare(
        "select id from users where username = ?"
    ).get(username);

    if (!target || target.id === req.session.userId) {
        return res.redirect("/u/" + username);
    }

    const existing = db.prepare(
        "select id from follows where follower_id = ? and following_id = ?"
    ).get(req.session.userId, target.id);

    if (existing) {
        db.prepare("delete from follows where id = ?").run(existing.id);
    } else {
        db.prepare(
            "insert or ignore into follows (follower_id, following_id) values (?, ?)"
        ).run(req.session.userId, target.id);
    }

    res.redirect("/u/" + username);
});

app.listen(port, () => {
    console.log("helloworld is running on port " + port);
});