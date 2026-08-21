require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
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
        secret:
            process.env.SESSION_SECRET ||
            "local-development-secret-change-me",

        resave: false,
        saveUninitialized: false,

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


/*
    helpers
*/

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
                bio,
                created_at
            from users
            where id = ?
            `
        )
        .get(req.session.userId);
}


function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    next();
}


function getReferer(req) {
    return req.get("referer") || "/feed";
}


/*
    health
*/

app.get("/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        service: "helloworld"
    });
});


/*
    home
*/

app.get("/", async (req, res) => {
    if (req.session.userId) {
        return res.redirect("/feed");
    }

    res.render("index");
});


/*
    register
*/

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
                error: "that username is already taken."
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
            .run(username, hash);

        const userId = result.lastInsertRowid;

        req.session.regenerate(error => {
            if (error) {
                console.error(error);
                return res
                    .status(500)
                    .send("something went wrong.");
            }

            req.session.userId = userId;

            req.session.save(error => {
                if (error) {
                    console.error(error);
                    return res
                        .status(500)
                        .send("something went wrong.");
                }

                res.redirect("/feed");
            });
        });
    } catch (error) {
        console.error("registration error:", error);

        res.render("register", {
            error: "something went wrong creating your account."
        });
    }
});


/*
    login
*/

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
                select *
                from users
                where username = ?
                `
            )
            .get(username);

        if (!user) {
            return res.render("login", {
                error: "we couldn't find that account."
            });
        }

        const valid = await bcrypt.compare(
            password,
            user.password
        );

        if (!valid) {
            return res.render("login", {
                error: "that password isn't correct."
            });
        }

        req.session.regenerate(error => {
            if (error) {
                console.error(error);
                return res
                    .status(500)
                    .send("something went wrong.");
            }

            req.session.userId = user.id;

            req.session.save(error => {
                if (error) {
                    console.error(error);
                    return res
                        .status(500)
                        .send("something went wrong.");
                }

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


/*
    logout
*/

app.post("/logout", requireLogin, (req, res) => {
    req.session.destroy(error => {
        if (error) {
            console.error(error);
        }

        res.clearCookie("connect.sid");
        res.redirect("/");
    });
});


/*
    feed
*/

app.get("/feed", requireLogin, async (req, res) => {
    try {
        const user = await currentUser(req);

        const posts = await db.prepare(`
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
                exists(
                    select 1
                    from likes
                    where likes.post_id = posts.id
                    and likes.user_id = ?
                ) as liked
            from posts
            join users on users.id = posts.user_id
            where posts.user_id = ?
            or posts.user_id in (
                select following_id
                from follows
                where follower_id = ?
            )
            order by posts.created_at desc
            limit 100
        `).all(user.id, user.id, user.id);

        const getComments = db.prepare(`
            select
                comments.id,
                comments.content,
                comments.created_at,
                users.username
            from comments
            join users on users.id = comments.user_id
            where comments.post_id = ?
            order by comments.created_at asc
        `);

        for (const post of posts) {
            post.comment_list = await getComments.all(post.id);
        }

        const communities = await db.prepare(`
            select
                communities.id,
                communities.name,
                communities.description,
                communities.created_at,
                0 as members
            from communities
            order by communities.created_at desc
        `).all();

        res.render("feed", {
            user,
            posts,
            communities
        });
    } catch (error) {
        console.error("feed error:", error);
        res.status(500).send("something went wrong.");
    }
});

/*
    create post
*/

app.post("/posts", requireLogin, async (req, res) => {
    try {
        const content = String(
            req.body.content || ""
        ).trim();

        if (!content || content.length > 500) {
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
        console.error("create post error:", error);

        res.status(500).send(
            "something went wrong creating your post."
        );
    }
});


/*
    delete own post
*/

app.post(
    "/posts/:id/delete",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(req.params.id);

            if (!Number.isInteger(postId)) {
                return res.redirect(getReferer(req));
            }

            await db
                .prepare(
                    `
                    delete from posts
                    where id = ?
                    and user_id = ?
                    `
                )
                .run(
                    postId,
                    req.session.userId
                );

            res.redirect(getReferer(req));
        } catch (error) {
            console.error(
                "delete post error:",
                error
            );

            res.status(500).send(
                "something went wrong deleting the post."
            );
        }
    }
);


/*
    like / unlike
*/

app.post(
    "/posts/:id/like",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(req.params.id);

            if (!Number.isInteger(postId)) {
                return res.redirect(getReferer(req));
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
                return res.redirect(getReferer(req));
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

            res.redirect(getReferer(req));
        } catch (error) {
            console.error(
                "like error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
    comments page
*/

app.get(
    "/posts/:id/comments",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(req.params.id);

            if (!Number.isInteger(postId)) {
                return res.status(404).send(
                    "post not found."
                );
            }

            const user = await currentUser(req);

            const post = await db
                .prepare(
                    `
                    select
                        posts.id,
                        posts.user_id,
                        posts.content,
                        posts.created_at,
                        users.username

                    from posts

                    join users
                        on users.id = posts.user_id

                    where posts.id = ?
                    `
                )
                .get(postId);

            if (!post) {
                return res.status(404).send(
                    "post not found."
                );
            }

            const comments = await db
                .prepare(
                    `
                    select
                        comments.id,
                        comments.content,
                        comments.created_at,
                        comments.user_id,
                        users.username

                    from comments

                    join users
                        on users.id = comments.user_id

                    where comments.post_id = ?

                    order by comments.created_at asc
                    `
                )
                .all(postId);

            const likes = await db
                .prepare(
                    `
                    select count(*) as count
                    from likes
                    where post_id = ?
                    `
                )
                .get(postId);

            const liked = await db
                .prepare(
                    `
                    select id
                    from likes
                    where post_id = ?
                    and user_id = ?
                    `
                )
                .get(
                    postId,
                    req.session.userId
                );

            res.render("comments", {
                user,
                post,
                comments,
                likes: Number(likes?.count || 0),
                liked: !!liked
            });
        } catch (error) {
            console.error(
                "comments page error:",
                error
            );

            res.status(500).send(
                "something went wrong loading the comments."
            );
        }
    }
);


/*
    create comment
*/

app.post(
    "/posts/:id/comments",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(req.params.id);

            const content = String(
                req.body.content || ""
            ).trim();

            if (
                !Number.isInteger(postId) ||
                !content ||
                content.length > 300
            ) {
                return res.redirect(
                    "/posts/" + postId + "/comments"
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
                return res.status(404).send(
                    "post not found."
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
                "/posts/" + postId + "/comments"
            );
        } catch (error) {
            console.error(
                "create comment error:",
                error
            );

            res.status(500).send(
                "something went wrong creating your comment."
            );
        }
    }
);


/*
    delete own comment
*/

app.post(
    "/comments/:id/delete",
    requireLogin,
    async (req, res) => {
        try {
            const commentId = Number(
                req.params.id
            );

            if (!Number.isInteger(commentId)) {
                return res.redirect("/feed");
            }

            const comment = await db
                .prepare(
                    `
                    select post_id
                    from comments
                    where id = ?
                    and user_id = ?
                    `
                )
                .get(
                    commentId,
                    req.session.userId
                );

            if (!comment) {
                return res.redirect("/feed");
            }

            await db
                .prepare(
                    `
                    delete from comments
                    where id = ?
                    and user_id = ?
                    `
                )
                .run(
                    commentId,
                    req.session.userId
                );

            res.redirect(
                "/posts/" +
                comment.post_id +
                "/comments"
            );
        } catch (error) {
            console.error(
                "delete comment error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
    profiles
*/

app.get(
    "/u/:username",
    requireLogin,
    async (req, res) => {
        try {
            const username = String(
                req.params.username || ""
            )
                .toLowerCase()
                .trim();

            const profileUser = await db
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

            if (!profileUser) {
                return res.status(404).send(
                    "user not found."
                );
            }

            const posts = await db
                .prepare(
                    `
                    select
                        posts.id,
                        posts.user_id,
                        posts.content,
                        posts.created_at,

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

                    where posts.user_id = ?

                    order by posts.created_at desc
                    `
                )
                .all(profileUser.id);

            const followers = await db
                .prepare(
                    `
                    select count(*) as count
                    from follows
                    where following_id = ?
                    `
                )
                .get(profileUser.id);

            const following = await db
                .prepare(
                    `
                    select count(*) as count
                    from follows
                    where follower_id = ?
                    `
                )
                .get(profileUser.id);

            const isFollowing =
                profileUser.id !==
                    req.session.userId &&
                !!(
                    await db
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
                            profileUser.id
                        )
                );

            const loggedInUser =
                await currentUser(req);

            res.render("profile", {
                user: profileUser,
                posts,
                followers:
                    Number(followers?.count || 0),
                following:
                    Number(following?.count || 0),
                isFollowing,
                currentUser: loggedInUser
            });
        } catch (error) {
            console.error(
                "profile error:",
                error
            );

            res.status(500).send(
                "something went wrong loading the profile."
            );
        }
    }
);


/*
    follow / unfollow
*/

app.post(
    "/u/:username/follow",
    requireLogin,
    async (req, res) => {
        try {
            const username = String(
                req.params.username || ""
            )
                .toLowerCase()
                .trim();

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
                            (
                                follower_id,
                                following_id
                            )

                        values
                            (?, ?)

                        on conflict (
                            follower_id,
                            following_id
                        )

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

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);

const ADMIN_PASSWORD = "SamanthaVT*374-SJpa";
const ADMIN_URL = "/mavellorinthal";

function requireAdmin(req, res, next) {
    if (!req.session.admin) {
        return res.redirect(ADMIN_URL);
    }

    next();
}

app.get(ADMIN_URL, (req, res) => {
    if (req.session.admin) {
        return res.redirect(ADMIN_URL + "/panel");
    }

    res.render("admin-login", {
        error: null
    });
});

app.post(ADMIN_URL, (req, res) => {
    const password = String(req.body.password || "");

    if (password !== ADMIN_PASSWORD) {
        return res.status(401).render("admin-login", {
            error: "incorrect password."
        });
    }

    req.session.admin = true;

    req.session.save(error => {
        if (error) {
            console.error(error);
            return res.status(500).send("something went wrong.");
        }

        res.redirect(ADMIN_URL + "/panel");
    });
});

app.post(ADMIN_URL + "/logout", requireAdmin, (req, res) => {
    req.session.admin = false;

    req.session.save(() => {
        res.redirect(ADMIN_URL);
    });
});

app.get(ADMIN_URL + "/panel", requireAdmin, async (req, res) => {
    try {
        const users = await db.prepare(`
            select
                users.id,
                users.username,
                users.bio,
                users.created_at,
                (
                    select count(*)
                    from posts
                    where posts.user_id = users.id
                ) as post_count
            from users
            order by users.created_at desc
        `).all();

        const posts = await db.prepare(`
            select
                posts.id,
                posts.content,
                posts.created_at,
                users.username
            from posts
            join users on users.id = posts.user_id
            order by posts.created_at desc
            limit 100
        `).all();

        const communities = await db.prepare(`
            select
                communities.id,
                communities.name,
                communities.description,
                communities.created_at
            from communities
            order by communities.created_at desc
        `).all();

        res.render("admin", {
            users,
            posts,
            communities
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("something went wrong.");
    }
});

app.post(ADMIN_URL + "/posts/:id/delete", requireAdmin, async (req, res) => {
    const postId = Number(req.params.id);

    if (!Number.isInteger(postId)) {
        return res.redirect(ADMIN_URL + "/panel");
    }

    try {
        await db.prepare(
            "delete from posts where id = ?"
        ).run(postId);

        res.redirect(ADMIN_URL + "/panel");
    } catch (error) {
        console.error(error);
        res.status(500).send("something went wrong.");
    }
});

app.post(ADMIN_URL + "/users/:id/delete", requireAdmin, async (req, res) => {
    const userId = Number(req.params.id);

    if (!Number.isInteger(userId)) {
        return res.redirect(ADMIN_URL + "/panel");
    }

    try {
        await db.prepare(
            "delete from users where id = ?"
        ).run(userId);

        res.redirect(ADMIN_URL + "/panel");
    } catch (error) {
        console.error(error);
        res.status(500).send("something went wrong.");
    }
});

app.post(ADMIN_URL + "/communities", requireAdmin, async (req, res) => {
    const name = String(req.body.name || "")
        .trim()
        .toLowerCase();

    const description = String(req.body.description || "")
        .trim();

    if (
        !/^[a-z0-9_-]{2,50}$/.test(name) ||
        description.length > 300
    ) {
        return res.redirect(ADMIN_URL + "/panel");
    }

    try {
        await db.prepare(`
            insert into communities (name, description)
            values (?, ?)
            on conflict (name) do nothing
        `).run(name, description);

        res.redirect(ADMIN_URL + "/panel");
    } catch (error) {
        console.error(error);
        res.status(500).send("something went wrong.");
    }
});

app.post(
    ADMIN_URL + "/communities/:id/delete",
    requireAdmin,
    async (req, res) => {
        const communityId = Number(req.params.id);

        if (!Number.isInteger(communityId)) {
            return res.redirect(ADMIN_URL + "/panel");
        }

        try {
            await db.prepare(
                "delete from communities where id = ?"
            ).run(communityId);

            res.redirect(ADMIN_URL + "/panel");
        } catch (error) {
            console.error(error);
            res.status(500).send("something went wrong.");
        }
    }
);


app.get("/c/:name", requireLogin, async (req, res) => {
    try {
        const name = String(req.params.name || "")
            .trim()
            .toLowerCase();

        const community = await db.prepare(`
            select
                id,
                name,
                description,
                created_at
            from communities
            where name = ?
        `).get(name);

        if (!community) {
            return res.status(404).send("community not found.");
        }

        const posts = await db.prepare(`
            select
                posts.id,
                posts.content,
                posts.created_at,
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
                exists(
                    select 1
                    from likes
                    where likes.post_id = posts.id
                    and likes.user_id = ?
                ) as liked
            from posts
            join users on users.id = posts.user_id
            where posts.community_id = ?
            order by posts.created_at desc
            limit 100
        `).all(req.session.userId, community.id);

        const getComments = db.prepare(`
            select
                comments.id,
                comments.content,
                comments.created_at,
                users.username
            from comments
            join users on users.id = comments.user_id
            where comments.post_id = ?
            order by comments.created_at asc
        `);

        for (const post of posts) {
            post.comment_list = await getComments.all(post.id);
        }

        res.render("community", {
            community,
            posts,
            user: currentUser(req)
        });
    } catch (error) {
        console.error("community error:", error);
        res.status(500).send("something went wrong.");
    }
});

/*
    404
*/

app.use((req, res) => {
    res.status(404).send(
        "page not found."
    );
});


/*
    errors
*/

app.use((error, req, res, next) => {
    console.error(
        "server error:",
        error
    );

    res.status(500).send(
        "something went wrong."
    );
});


/*
    start
*/

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
            "failed to start server:"
        );

        console.error(error);

        process.exit(1);
    }
}

startServer();
