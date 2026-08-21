require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");
const db = require("./database");

const app = express();
const port = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";

if (
    isProduction &&
    (!process.env.SESSION_SECRET ||
        process.env.SESSION_SECRET.length < 32)
) {
    throw new Error(
        "SESSION_SECRET must be set to a long random value in production."
    );
}

const sessionDir = path.resolve("./sessions");

fs.mkdirSync(sessionDir, {
    recursive: true
});

app.set("view engine", "ejs");
app.set("trust proxy", 1);

app.use(
    express.urlencoded({
        extended: false,
        limit: "20kb"
    })
);

app.use(
    session({
        store: new SQLiteStore({
            db: "sessions.db",
            dir: sessionDir,
            concurrentDB: true
        }),

        secret:
            process.env.SESSION_SECRET ||
            "local-development-secret-change-me",

        resave: false,
        saveUninitialized: false,
        rolling: true,

        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: isProduction,
            maxAge: 1000 * 60 * 60 * 24 * 30
        }
    })
);

app.use(
    express.static(path.join(__dirname, "public"), {
        maxAge: isProduction ? "7d" : 0
    })
);

app.locals.formatDate = date => {
    return new Date(date).toLocaleString().toLowerCase();
};

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    next();
}

async function currentUser(req) {
    if (!req.session.userId) {
        return null;
    }

    return await db
        .prepare(
            `
            select
                id,
                username,
                bio
            from users
            where id = ?
            `
        )
        .get(req.session.userId);
}

/* health */

app.get("/health", async (req, res) => {
    try {
        await db.pool.query("select 1");

        res.status(200).json({
            status: "ok",
            service: "helloworld",
            database: "connected"
        });
    } catch (error) {
        console.error("health check database error:", error);

        res.status(500).json({
            status: "error",
            service: "helloworld",
            database: "disconnected"
        });
    }
});

/* home */

app.get("/", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/feed");
    }

    res.render("index");
});

/* register */

app.get("/register", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/feed");
    }

    res.render("register", {
        error: null
    });
});

app.post("/register", async (req, res) => {
    try {
        const username = String(
            req.body.username || ""
        )
            .trim()
            .toLowerCase();

        const password = String(
            req.body.password || ""
        );

        if (!/^[a-z0-9_]{3,30}$/.test(username)) {
            return res.render("register", {
                error:
                    "usernames can only use lowercase letters, numbers, and underscores."
            });
        }

        if (password.length < 8) {
            return res.render("register", {
                error:
                    "your password needs at least 8 characters."
            });
        }

        const existing = await db
            .prepare(
                `
                select id
                from users
                where username = ?
                `
            )
            .get(username);

        if (existing) {
            return res.render("register", {
                error:
                    "that username is already taken."
            });
        }

        const hash = await bcrypt.hash(password, 12);

        const result = await db
            .prepare(
                `
                insert into users
                    (username, password)
                values
                    (?, ?)
                returning id
                `
            )
            .get(username, hash);

        req.session.regenerate(error => {
            if (error) {
                console.error(
                    "session regeneration error:",
                    error
                );

                return res
                    .status(500)
                    .send("something went wrong.");
            }

            req.session.userId = result.id;

            req.session.save(error => {
                if (error) {
                    console.error(
                        "session save error:",
                        error
                    );

                    return res
                        .status(500)
                        .send("something went wrong.");
                }

                res.redirect("/feed");
            });
        });
    } catch (error) {
        console.error("registration error:", error);

        res.status(500).send(
            "something went wrong while creating your account."
        );
    }
});

/* login */

app.get("/login", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/feed");
    }

    res.render("login", {
        error: null
    });
});

app.post("/login", async (req, res) => {
    try {
        const username = String(
            req.body.username || ""
        )
            .trim()
            .toLowerCase();

        const password = String(
            req.body.password || ""
        );

        const user = await db
            .prepare(
                `
                select
                    id,
                    username,
                    password,
                    bio
                from users
                where username = ?
                `
            )
            .get(username);

        if (!user) {
            return res.render("login", {
                error:
                    "we couldn't find that account."
            });
        }

        const valid = await bcrypt.compare(
            password,
            user.password
        );

        if (!valid) {
            return res.render("login", {
                error:
                    "that password isn't correct."
            });
        }

        req.session.regenerate(error => {
            if (error) {
                console.error(
                    "session regeneration error:",
                    error
                );

                return res.render("login", {
                    error:
                        "something went wrong while logging you in."
                });
            }

            req.session.userId = user.id;

            req.session.save(error => {
                if (error) {
                    console.error(
                        "session save error:",
                        error
                    );

                    return res.render("login", {
                        error:
                            "something went wrong while logging you in."
                    });
                }

                console.log(
                    "logged in:",
                    user.username,
                    "user id:",
                    user.id
                );

                res.redirect("/feed");
            });
        });
    } catch (error) {
        console.error("login error:", error);

        res.render("login", {
            error:
                "something went wrong while logging you in."
        });
    }
});

/* logout */

app.post("/logout", requireLogin, (req, res) => {
    req.session.destroy(error => {
        if (error) {
            console.error(
                "logout session error:",
                error
            );
        }

        res.clearCookie("connect.sid");
        res.redirect("/");
    });
});

/* feed */

app.get("/feed", requireLogin, async (req, res) => {
    try {
        const user = await currentUser(req);

        if (!user) {
            req.session.destroy(() => {
                res.redirect("/login");
            });

            return;
        }

        const posts = await db
            .prepare(
                `
                select
                    posts.*,
                    users.username,

                    (
                        select count(*)
                        from likes
                        where likes.post_id = posts.id
                    ) as likes,

                    (
                        select count(*)
                        from comments
                        where comments.post_id = posts.id
                    ) as comments,

                    exists (
                        select 1
                        from likes
                        where likes.post_id = posts.id
                        and likes.user_id = ?
                    ) as liked

                from posts

                join users
                    on users.id = posts.user_id

                where
                    posts.user_id = ?

                    or posts.user_id in (
                        select following_id
                        from follows
                        where follower_id = ?
                    )

                order by posts.created_at desc

                limit 100
                `
            )
            .all(
                user.id,
                user.id,
                user.id
            );

        const getComments = db.prepare(
            `
            select
                comments.id,
                comments.content,
                comments.created_at,
                users.username

            from comments

            join users
                on users.id = comments.user_id

            where comments.post_id = ?

            order by comments.created_at asc
            `
        );

        for (const post of posts) {
            post.comment_list =
                await getComments.all(post.id);
        }

        res.render("feed", {
            user,
            posts
        });
    } catch (error) {
        console.error("feed error:", error);

        res.status(500).send(
            "something went wrong loading the feed."
        );
    }
});

/* create post */

app.post("/posts", requireLogin, async (req, res) => {
    try {
        const content = String(
            req.body.content || ""
        ).trim();

        if (
            !content ||
            content.length > 500
        ) {
            return res.redirect("/feed");
        }

        await db
            .prepare(
                `
                insert into posts
                    (user_id, content)
                values
                    (?, ?)
                `
            )
            .run(
                req.session.userId,
                content
            );

        res.redirect("/feed");
    } catch (error) {
        console.error(
            "create post error:",
            error
        );

        res.status(500).send(
            "something went wrong creating your post."
        );
    }
});

/* like */

app.post(
    "/posts/:id/like",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (!Number.isInteger(postId)) {
                return res.redirect("/feed");
            }

            const existing = await db
                .prepare(
                    `
                    select id
                    from likes
                    where user_id = ?
                    and post_id = ?
                    `
                )
                .get(
                    req.session.userId,
                    postId
                );

            if (existing) {
                await db
                    .prepare(
                        `
                        delete from likes
                        where id = ?
                        `
                    )
                    .run(existing.id);
            } else {
                await db
                    .prepare(
                        `
                        insert into likes
                            (user_id, post_id)
                        values
                            (?, ?)
                        on conflict (user_id, post_id)
                        do nothing
                        `
                    )
                    .run(
                        req.session.userId,
                        postId
                    );
            }

            res.redirect(
                req.get("referer") || "/feed"
            );
        } catch (error) {
            console.error(
                "like error:",
                error
            );

            res.redirect("/feed");
        }
    }
);

app.post("/posts/:id/delete", requireLogin, (req, res) => {
    const postId = Number(req.params.id);

    if (!Number.isInteger(postId)) {
        return res.redirect(req.get("referer") || "/feed");
    }

    const post = db.prepare(
        "select id from posts where id = ? and user_id = ?"
    ).get(postId, req.session.userId);

    if (!post) {
        return res.redirect(req.get("referer") || "/feed");
    }

    db.prepare(
        "delete from posts where id = ? and user_id = ?"
    ).run(postId, req.session.userId);

    res.redirect(req.get("referer") || "/feed");
});

/* comments */

app.post(
    "/posts/:id/comments",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            const content = String(
                req.body.content || ""
            ).trim();

            if (
                !Number.isInteger(postId) ||
                !content ||
                content.length > 300
            ) {
                return res.redirect(
                    req.get("referer") || "/feed"
                );
            }

            const post = await db
                .prepare(
                    `
                    select id
                    from posts
                    where id = ?
                    `
                )
                .get(postId);

            if (!post) {
                return res.redirect(
                    req.get("referer") || "/feed"
                );
            }

            await db
                .prepare(
                    `
                    insert into comments
                        (user_id, post_id, content)
                    values
                        (?, ?, ?)
                    `
                )
                .run(
                    req.session.userId,
                    postId,
                    content
                );

            res.redirect(
                req.get("referer") || "/feed"
            );
        } catch (error) {
            console.error(
                "comment error:",
                error
            );

            res.redirect(
                req.get("referer") || "/feed"
            );
        }
    }
);

/* profile */

app.get(
    "/u/:username",
    requireLogin,
    async (req, res) => {
        try {
            const username = String(
                req.params.username
            ).toLowerCase();

            const user = await db
                .prepare(
                    `
                    select
                        id,
                        username,
                        bio,
                        created_at
                    from users
                    where username = ?
                    `
                )
                .get(username);

            if (!user) {
                return res
                    .status(404)
                    .send("user not found.");
            }

            const posts = await db
                .prepare(
                    `
                    select
                        posts.*,
                        users.username,

                        (
                            select count(*)
                            from likes
                            where likes.post_id = posts.id
                        ) as likes,

                        (
                            select count(*)
                            from comments
                            where comments.post_id = posts.id
                        ) as comments

                    from posts

                    join users
                        on users.id = posts.user_id

                    where posts.user_id = ?

                    order by posts.created_at desc
                    `
                )
                .all(user.id);

            const getComments = db.prepare(
                `
                select
                    comments.id,
                    comments.content,
                    comments.created_at,
                    users.username

                from comments

                join users
                    on users.id = comments.user_id

                where comments.post_id = ?

                order by comments.created_at asc
                `
            );

            for (const post of posts) {
                post.comment_list =
                    await getComments.all(post.id);
            }

            const followers = await db
                .prepare(
                    `
                    select count(*) as count
                    from follows
                    where following_id = ?
                    `
                )
                .get(user.id);

            const following = await db
                .prepare(
                    `
                    select count(*) as count
                    from follows
                    where follower_id = ?
                    `
                )
                .get(user.id);

            const isFollowing =
                user.id !== req.session.userId &&
                !!(await db
                    .prepare(
                        `
                        select id
                        from follows
                        where follower_id = ?
                        and following_id = ?
                        `
                    )
                    .get(
                        req.session.userId,
                        user.id
                    ));

            res.render("profile", {
                user,
                posts,
                followers: Number(
                    followers.count
                ),
                following: Number(
                    following.count
                ),
                isFollowing,
                currentUser:
                    await currentUser(req)
            });
        } catch (error) {
            console.error(
                "profile error:",
                error
            );

            res.status(500).send(
                "something went wrong loading this profile."
            );
        }
    }
);

/* follow */

app.post(
    "/u/:username/follow",
    requireLogin,
    async (req, res) => {
        try {
            const username = String(
                req.params.username
            ).toLowerCase();

            const target = await db
                .prepare(
                    `
                    select id
                    from users
                    where username = ?
                    `
                )
                .get(username);

            if (
                !target ||
                target.id === req.session.userId
            ) {
                return res.redirect(
                    "/u/" + username
                );
            }

            const existing = await db
                .prepare(
                    `
                    select id
                    from follows
                    where follower_id = ?
                    and following_id = ?
                    `
                )
                .get(
                    req.session.userId,
                    target.id
                );

            if (existing) {
                await db
                    .prepare(
                        `
                        delete from follows
                        where id = ?
                        `
                    )
                    .run(existing.id);
            } else {
                await db
                    .prepare(
                        `
                        insert into follows
                            (follower_id, following_id)
                        values
                            (?, ?)
                        on conflict
                            (follower_id, following_id)
                        do nothing
                        `
                    )
                    .run(
                        req.session.userId,
                        target.id
                    );
            }

            res.redirect(
                "/u/" + username
            );
        } catch (error) {
            console.error(
                "follow error:",
                error
            );

            res.redirect(
                "/u/" +
                    String(
                        req.params.username
                    ).toLowerCase()
            );
        }
    }
);

app.get("/posts/:id/comments", requireLogin, (req, res) => {
    const postId = Number(req.params.id);

    if (!Number.isInteger(postId)) {
        return res.status(404).send("post not found.");
    }

    const post = db.prepare(`
        select
            posts.*,
            users.username,
            (select count(*) from likes where likes.post_id = posts.id) as likes,
            exists(
                select 1
                from likes
                where likes.post_id = posts.id
                and likes.user_id = ?
            ) as liked
        from posts
        join users on users.id = posts.user_id
        where posts.id = ?
    `).get(req.session.userId, postId);

    if (!post) {
        return res.status(404).send("post not found.");
    }

    const comments = db.prepare(`
        select
            comments.id,
            comments.content,
            comments.created_at,
            users.username
        from comments
        join users on users.id = comments.user_id
        where comments.post_id = ?
        order by comments.created_at asc
    `).all(postId);

    res.render("comments", {
        user: currentUser(req),
        post,
        comments
    });
});

/* 404 */

app.use((req, res) => {
    res.status(404).send(
        "page not found."
    );
});

/* startup */

async function startServer() {
    try {
        await db.initializeDatabase();

        app.listen(port, () => {
            console.log(
                "helloworld is running on port " +
                    port
            );
        });
    } catch (error) {
        console.error(
            "failed to start server:",
            error
        );

        process.exit(1);
    }
}

startServer();
