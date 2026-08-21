require("dotenv").config();

const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const db = require("./database");

const app = express();

const port = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";

const sessionSecret = process.env.SESSION_SECRET;

if (isProduction && (!sessionSecret || sessionSecret.length < 32)) {
    throw new Error("SESSION_SECRET must be set to a long random value in production.");
}

const adminPath = "/qzmxvtrpalks";
const adminPassword =
    process.env.ADMIN_PASSWORD || "SamanthaVT*374-SJpa";

app.set("view engine", "ejs");
app.set("trust proxy", 1);

app.use(express.urlencoded({
    extended: false,
    limit: "20kb"
}));

app.use(express.static(
    require("path").join(__dirname, "public"),
    {
        maxAge: isProduction ? "7d" : 0
    }
));

app.use(session({
    store: new pgSession({
        pool: db.pool,
        tableName: "user_sessions",
        createTableIfMissing: false
    }),

    secret: sessionSecret || "local-development-secret-change-me",

    resave: false,
    saveUninitialized: false,
    rolling: true,

    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: isProduction,
        maxAge: 1000 * 60 * 60 * 24 * 30
    }
}));

app.locals.formatDate = function (date) {
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

    return await db.prepare(`
        select
            id,
            username,
            display_name,
            bio,
            created_at
        from users
        where id = ?
    `).get(req.session.userId);
}

function redirectBack(req, fallback = "/feed") {
    return req.get("referer") || fallback;
}

/* health */

app.get("/health", async (req, res) => {
    try {
        await db.pool.query("select 1");

        res.status(200).json({
            status: "ok",
            service: "helloworld"
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            status: "error",
            service: "helloworld"
        });
    }
});

/* home */

app.get("/", async (req, res) => {
    if (req.session.userId) {
        return res.redirect("/feed");
    }

    res.render("index");
});

/* register */

app.get("/register", async (req, res) => {
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
        ).trim().toLowerCase();

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

        const existing = await db.prepare(`
            select id
            from users
            where username = ?
        `).get(username);

        if (existing) {
            return res.render("register", {
                error: "that username is already taken."
            });
        }

        const hash = await bcrypt.hash(password, 12);

        const result = await db.prepare(`
            insert into users (
                username,
                password
            )
            values (?, ?)
            returning id
        `).run(username, hash);

        await new Promise((resolve, reject) => {
            req.session.regenerate(error => {
                if (error) {
                    reject(error);
                } else {
                    resolve();
                }
            });
        });

        req.session.userId = result.lastInsertRowid;

        await new Promise((resolve, reject) => {
            req.session.save(error => {
                if (error) {
                    reject(error);
                } else {
                    resolve();
                }
            });
        });

        res.redirect("/feed");
    } catch (error) {
        console.error("registration error:", error);

        res.status(500).send(
            "something went wrong while creating your account."
        );
    }
});

/* login */

app.get("/login", async (req, res) => {
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
        ).trim().toLowerCase();

        const password = String(
            req.body.password || ""
        );

        const user = await db.prepare(`
            select *
            from users
            where username = ?
        `).get(username);

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

        await new Promise((resolve, reject) => {
            req.session.regenerate(error => {
                if (error) {
                    reject(error);
                } else {
                    resolve();
                }
            });
        });

        req.session.userId = user.id;

        await new Promise((resolve, reject) => {
            req.session.save(error => {
                if (error) {
                    reject(error);
                } else {
                    resolve();
                }
            });
        });

        res.redirect("/feed");
    } catch (error) {
        console.error("login error:", error);

        res.status(500).send(
            "something went wrong while logging you in."
        );
    }
});

/* logout */

app.post("/logout", requireLogin, (req, res) => {
    req.session.destroy(error => {
        if (error) {
            console.error(error);
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
            req.session.destroy(() => {});
            return res.redirect("/login");
        }

        const posts = await db.prepare(`
            select
                posts.*,

                users.username,
                users.display_name,

                communities.name as community_name,

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

            left join communities
                on communities.id = posts.community_id

            order by posts.created_at desc

            limit 100
        `).all(user.id);

        const getComments = db.prepare(`
            select
                comments.id,
                comments.content,
                comments.created_at,
                users.username,
                users.display_name
            from comments

            join users
                on users.id = comments.user_id

            where comments.post_id = ?

            order by comments.created_at asc
        `);

        for (const post of posts) {
            post.comment_list =
                await getComments.all(post.id);
        }

        const communities = await db.prepare(`
            select
                communities.*,

                (
                    select count(*)
                    from posts
                    where posts.community_id = communities.id
                ) as post_count

            from communities

            order by communities.name asc

            limit 100
        `).all();

        res.render("feed", {
            user,
            posts,
            communities
        });

    } catch (error) {
        console.error("feed error:", error);

        res.status(500).send(
            "something went wrong while loading the feed."
        );
    }
});
/* create post */

app.post("/posts", requireLogin, async (req, res) => {
    try {
        const content = String(
            req.body.content || ""
        ).trim();

        const communityId = req.body.community_id
            ? Number(req.body.community_id)
            : null;

        if (!content || content.length > 500) {
            return res.redirect("/feed");
        }

        if (
            communityId !== null &&
            !Number.isInteger(communityId)
        ) {
            return res.redirect("/feed");
        }

        await db.prepare(`
            insert into posts (
                user_id,
                community_id,
                content
            )
            values (?, ?, ?)
        `).run(
            req.session.userId,
            communityId,
            content
        );

        res.redirect("/feed");
    } catch (error) {
        console.error("post creation error:", error);

        res.status(500).send(
            "something went wrong while creating your post."
        );
    }
});

/* delete own post */

app.post("/posts/:id/delete", requireLogin, async (req, res) => {
    try {
        const postId = Number(req.params.id);

        if (!Number.isInteger(postId)) {
            return res.redirect(redirectBack(req));
        }

        await db.prepare(`
            delete from posts
            where id = ?
            and user_id = ?
        `).run(
            postId,
            req.session.userId
        );

        res.redirect(redirectBack(req));
    } catch (error) {
        console.error("post deletion error:", error);

        res.status(500).send(
            "something went wrong while deleting the post."
        );
    }
});

/* like */

app.post("/posts/:id/like", requireLogin, async (req, res) => {
    try {
        const postId = Number(req.params.id);

        if (!Number.isInteger(postId)) {
            return res.redirect(redirectBack(req));
        }

        const existing = await db.prepare(`
            select id
            from likes
            where user_id = ?
            and post_id = ?
        `).get(
            req.session.userId,
            postId
        );

        if (existing) {
            await db.prepare(`
                delete from likes
                where id = ?
            `).run(existing.id);
        } else {
            await db.prepare(`
                insert into likes (
                    user_id,
                    post_id
                )
                values (?, ?)
                on conflict (
                    user_id,
                    post_id
                )
                do nothing
            `).run(
                req.session.userId,
                postId
            );
        }

        res.redirect(redirectBack(req));
    } catch (error) {
        console.error("like error:", error);

        res.status(500).send(
            "something went wrong."
        );
    }
});

/* comment page */

app.get("/posts/:id/comments", requireLogin, async (req, res) => {
    try {
        const postId = Number(req.params.id);

        if (!Number.isInteger(postId)) {
            return res.status(404).send(
                "post not found."
            );
        }

        const post = await db.prepare(`
            select
                posts.*,
                users.username,
                users.display_name,
                communities.name as community_name,

                (
                    select count(*)
                    from likes
                    where likes.post_id = posts.id
                ) as likes

            from posts

            join users
                on users.id = posts.user_id

            left join communities
                on communities.id = posts.community_id

            where posts.id = ?
        `).get(postId);

        if (!post) {
            return res.status(404).send(
                "post not found."
            );
        }

        const comments = await db.prepare(`
            select
                comments.*,
                users.username,
                users.display_name
            from comments
            join users
                on users.id = comments.user_id
            where comments.post_id = ?
            order by comments.created_at asc
        `).all(postId);

        const user = await currentUser(req);

        res.render("comments", {
            user,
            post,
            comments
        });
    } catch (error) {
        console.error("comments page error:", error);

        res.status(500).send(
            "something went wrong while loading the comments."
        );
    }
});

/* create comment */

app.post("/posts/:id/comments", requireLogin, async (req, res) => {
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

        const post = await db.prepare(`
            select id
            from posts
            where id = ?
        `).get(postId);

        if (!post) {
            return res.status(404).send(
                "post not found."
            );
        }

        await db.prepare(`
            insert into comments (
                user_id,
                post_id,
                content
            )
            values (?, ?, ?)
        `).run(
            req.session.userId,
            postId,
            content
        );

        res.redirect(
            "/posts/" + postId + "/comments"
        );
    } catch (error) {
        console.error("comment error:", error);

        res.status(500).send(
            "something went wrong while posting your comment."
        );
    }
});

/* profile */

app.get("/u/:username", requireLogin, async (req, res) => {
    try {
        const username = String(
            req.params.username || ""
        ).toLowerCase();

        const user = await db.prepare(`
            select
                id,
                username,
                display_name,
                bio,
                created_at
            from users
            where username = ?
        `).get(username);

        if (!user) {
            return res.status(404).send(
                "user not found."
            );
        }

        const posts = await db.prepare(`
            select
                posts.*,
                communities.name as community_name,

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

            left join communities
                on communities.id = posts.community_id

            where posts.user_id = ?

            order by posts.created_at desc
        `).all(user.id);

        const followers = await db.prepare(`
            select count(*) as count
            from follows
            where following_id = ?
        `).get(user.id);

        const following = await db.prepare(`
            select count(*) as count
            from follows
            where follower_id = ?
        `).get(user.id);

        const isFollowing =
            user.id !== req.session.userId &&
            !!await db.prepare(`
                select id
                from follows
                where follower_id = ?
                and following_id = ?
            `).get(
                req.session.userId,
                user.id
            );

        res.render("profile", {
            user,
            posts,
            followers: followers.count,
            following: following.count,
            isFollowing,
            currentUser: await currentUser(req)
        });
    } catch (error) {
        console.error("profile error:", error);

        res.status(500).send(
            "something went wrong while loading the profile."
        );
    }
});

/* profile customization */

app.get("/settings/profile", requireLogin, async (req, res) => {
    const user = await currentUser(req);

    res.render("profile-settings", {
        user,
        error: null
    });
});

app.post("/settings/profile", requireLogin, async (req, res) => {
    try {
        const displayName = String(
            req.body.display_name || ""
        ).trim();

        const bio = String(
            req.body.bio || ""
        ).trim();

        if (displayName.length > 40) {
            return res.render("profile-settings", {
                user: await currentUser(req),
                error: "your display name is too long."
            });
        }

        if (bio.length > 500) {
            return res.render("profile-settings", {
                user: await currentUser(req),
                error: "your bio is too long."
            });
        }

        await db.prepare(`
            update users
            set
                display_name = ?,
                bio = ?
            where id = ?
        `).run(
            displayName,
            bio,
            req.session.userId
        );

        const updated = await currentUser(req);

        res.redirect(
            "/u/" + updated.username
        );
    } catch (error) {
        console.error("profile update error:", error);

        res.status(500).send(
            "something went wrong while updating your profile."
        );
    }
});

/* follow */

app.post("/u/:username/follow", requireLogin, async (req, res) => {
    try {
        const username = String(
            req.params.username || ""
        ).toLowerCase();

        const target = await db.prepare(`
            select id
            from users
            where username = ?
        `).get(username);

        if (
            !target ||
            target.id === req.session.userId
        ) {
            return res.redirect(
                "/u/" + username
            );
        }

        const existing = await db.prepare(`
            select id
            from follows
            where follower_id = ?
            and following_id = ?
        `).get(
            req.session.userId,
            target.id
        );

        if (existing) {
            await db.prepare(`
                delete from follows
                where id = ?
            `).run(existing.id);
        } else {
            await db.prepare(`
                insert into follows (
                    follower_id,
                    following_id
                )
                values (?, ?)
                on conflict (
                    follower_id,
                    following_id
                )
                do nothing
            `).run(
                req.session.userId,
                target.id
            );
        }

        res.redirect(
            "/u/" + username
        );
    } catch (error) {
        console.error("follow error:", error);

        res.status(500).send(
            "something went wrong."
        );
    }
});

/* communities */

app.get("/communities", requireLogin, async (req, res) => {
    try {
        const communities = await db.prepare(`
            select
                communities.*,

                (
                    select count(*)
                    from posts
                    where posts.community_id = communities.id
                ) as post_count

            from communities
            order by communities.name asc
        `).all();

        res.render("communities", {
            user: await currentUser(req),
            communities
        });
    } catch (error) {
        console.error("communities error:", error);

        res.status(500).send(
            "something went wrong while loading communities."
        );
    }
});

app.get("/c/:name", requireLogin, async (req, res) => {
    try {
        const name = String(
            req.params.name || ""
        ).toLowerCase();

        const community = await db.prepare(`
            select *
            from communities
            where lower(name) = ?
        `).get(name);

        if (!community) {
            return res.status(404).send(
                "community not found."
            );
        }

        const posts = await db.prepare(`
            select
                posts.*,
                users.username,
                users.display_name,

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

            where posts.community_id = ?

            order by posts.created_at desc
        `).all(community.id);

        res.render("community", {
            user: await currentUser(req),
            community,
            posts
        });
    } catch (error) {
        console.error("community page error:", error);

        res.status(500).send(
            "something went wrong while loading this community."
        );
    }
});

/* hidden admin login */

app.get(adminPath, (req, res) => {
    if (req.session.admin) {
        return res.redirect(
            adminPath + "/dashboard"
        );
    }

    res.render("admin-login", {
        error: null
    });
});

app.post(adminPath, (req, res) => {
    const password = String(
        req.body.password || ""
    );

    if (password !== adminPassword) {
        return res.render("admin-login", {
            error: "incorrect password."
        });
    }

    req.session.admin = true;

    req.session.save(error => {
        if (error) {
            console.error(error);

            return res.status(500).send(
                "something went wrong."
            );
        }

        res.redirect(
            adminPath + "/dashboard"
        );
    });
});

function requireAdmin(req, res, next) {
    if (!req.session.admin) {
        return res.redirect(adminPath);
    }

    next();
}

/* admin dashboard */

app.get(
    adminPath + "/dashboard",
    requireAdmin,
    async (req, res) => {
        try {
            const users = await db.prepare(`
                select
                    id,
                    username,
                    display_name,
                    bio,
                    created_at
                from users
                order by created_at desc
                limit 500
            `).all();

            const posts = await db.prepare(`
                select
                    posts.id,
                    posts.content,
                    posts.created_at,
                    users.username,
                    communities.name as community_name
                from posts
                join users
                    on users.id = posts.user_id
                left join communities
                    on communities.id = posts.community_id
                order by posts.created_at desc
                limit 500
            `).all();

            const communities = await db.prepare(`
                select
                    communities.*,

                    (
                        select count(*)
                        from posts
                        where posts.community_id = communities.id
                    ) as post_count

                from communities
                order by communities.created_at desc
            `).all();

            res.render("admin", {
                users,
                posts,
                communities
            });
        } catch (error) {
            console.error("admin error:", error);

            res.status(500).send(
                "something went wrong while loading the admin panel."
            );
        }
    }
);

/* admin logout */

app.post(
    adminPath + "/logout",
    requireAdmin,
    (req, res) => {
        req.session.admin = false;

        res.redirect(adminPath);
    }
);

/* admin delete post */

app.post(
    adminPath + "/posts/:id/delete",
    requireAdmin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (!Number.isInteger(postId)) {
                return res.redirect(
                    adminPath + "/dashboard"
                );
            }

            await db.prepare(`
                delete from posts
                where id = ?
            `).run(postId);

            res.redirect(
                adminPath + "/dashboard"
            );
        } catch (error) {
            console.error(
                "admin post deletion error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);

/* admin delete account */

app.post(
    adminPath + "/users/:id/delete",
    requireAdmin,
    async (req, res) => {
        try {
            const userId = Number(
                req.params.id
            );

            if (!Number.isInteger(userId)) {
                return res.redirect(
                    adminPath + "/dashboard"
                );
            }

            await db.prepare(`
                delete from users
                where id = ?
            `).run(userId);

            res.redirect(
                adminPath + "/dashboard"
            );
        } catch (error) {
            console.error(
                "admin account deletion error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);

/* admin create community */

app.post(
    adminPath + "/communities/create",
    requireAdmin,
    async (req, res) => {
        try {
            const name = String(
                req.body.name || ""
            ).trim().toLowerCase();

            const description = String(
                req.body.description || ""
            ).trim();

            if (
                !/^[a-z0-9_-]{2,50}$/.test(name)
            ) {
                return res.status(400).send(
                    "community names can only contain lowercase letters, numbers, underscores, and hyphens."
                );
            }

            if (description.length > 300) {
                return res.status(400).send(
                    "community description is too long."
                );
            }

            await db.prepare(`
                insert into communities (
                    name,
                    description
                )
                values (?, ?)
                on conflict (name)
                do nothing
            `).run(
                name,
                description
            );

            res.redirect(
                adminPath + "/dashboard"
            );
        } catch (error) {
            console.error(
                "community creation error:",
                error
            );

            res.status(500).send(
                "something went wrong while creating the community."
            );
        }
    }
);

/* admin delete community */

app.post(
    adminPath + "/communities/:id/delete",
    requireAdmin,
    async (req, res) => {
        try {
            const communityId = Number(
                req.params.id
            );

            if (!Number.isInteger(communityId)) {
                return res.redirect(
                    adminPath + "/dashboard"
                );
            }

            await db.prepare(`
                delete from communities
                where id = ?
            `).run(communityId);

            res.redirect(
                adminPath + "/dashboard"
            );
        } catch (error) {
            console.error(
                "community deletion error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);

/* 404 */

app.use((req, res) => {
    res.status(404).send(
        "page not found."
    );
});

/* startup */

async function start() {
    try {
        await db.initializeDatabase();

        app.listen(port, () => {
            console.log(
                "helloworld is running on port " + port
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

start();
