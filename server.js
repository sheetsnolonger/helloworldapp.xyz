require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const db = require("./database");

const app = express();

const port = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";

const adminUrl = "/mavellorinthal";
const adminPassword = "SamanthaVT*374-SJpa";

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
        store: new PgSession({
            pool: db.pool,
            tableName: "user_sessions",
            createTableIfMissing: true
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
    express.static(require("path").join(__dirname, "public"), {
        maxAge: isProduction ? "7d" : 0
    })
);

app.locals.formatDate = date => {
    return new Date(date)
        .toLocaleString()
        .toLowerCase();
};

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.admin) {
        return res.redirect(adminUrl);
    }

    next();
}

async function currentUser(req) {
    if (!req.session.userId) {
        return null;
    }

    return db.prepare(`
        select
            id,
            username,
            bio,
            created_at
        from users
        where id = ?
    `).get(req.session.userId);
}


/*
 * health
 */

app.get("/health", async (req, res) => {
    try {
        await db.pool.query("select 1");

        res.status(200).json({
            status: "ok",
            service: "helloworld",
            database: "connected"
        });
    } catch (error) {
        console.error("health check failed:", error);

        res.status(503).json({
            status: "error",
            service: "helloworld",
            database: "disconnected"
        });
    }
});


/*
 * home
 */

app.get("/", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/feed");
    }

    res.render("index");
});


/*
 * register
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

        const existing = await db.prepare(`
            select id
            from users
            where username = ?
        `).get(username);

        if (existing) {
            return res.render("register", {
                error:
                    "that username is already taken."
            });
        }

        const hash = await bcrypt.hash(
            password,
            12
        );

        const result = await db.prepare(`
            insert into users (
                username,
                password
            )
            values (?, ?)
            returning id
        `).run(
            username,
            hash
        );

        req.session.regenerate(error => {
            if (error) {
                console.error(error);
                return res
                    .status(500)
                    .send("something went wrong.");
            }

            req.session.userId =
                result.lastInsertRowid;

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

        res.status(500).send(
            "something went wrong."
        );
    }
});


/*
 * login
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

        const user = await db.prepare(`
            select *
            from users
            where username = ?
        `).get(username);

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

        res.status(500).send(
            "something went wrong."
        );
    }
});


/*
 * logout
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
 * feed
 */

app.get("/feed", requireLogin, async (req, res) => {
    try {
        const user = await currentUser(req);

        const posts = await db.prepare(`
            select
                posts.id,
                posts.user_id,
                posts.community_id,
                posts.content,
                posts.created_at,

                users.username,

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

                exists(
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
                users.username

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
                communities.id,
                communities.name,
                communities.description,
                communities.created_at,

                (
                    select count(*)
                    from posts
                    where posts.community_id = communities.id
                ) as post_count

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

        res.status(500).send(
            "something went wrong."
        );
    }
});


/*
 * create post
 */

app.post("/posts", requireLogin, async (req, res) => {
    try {
        const content = String(
            req.body.content || ""
        ).trim();

        const communityIdRaw = String(
            req.body.community_id || ""
        ).trim();

        let communityId = null;

        if (communityIdRaw !== "") {
            communityId = Number(
                communityIdRaw
            );

            if (!Number.isInteger(communityId)) {
                return res.redirect(
                    req.get("referer") || "/feed"
                );
            }

            const community =
                await db.prepare(`
                    select id
                    from communities
                    where id = ?
                `).get(communityId);

            if (!community) {
                return res.redirect(
                    req.get("referer") || "/feed"
                );
            }
        }

        if (
            !content ||
            content.length > 500
        ) {
            return res.redirect(
                req.get("referer") || "/feed"
            );
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

        res.redirect(
            req.get("referer") || "/feed"
        );
    } catch (error) {
        console.error("create post error:", error);

        res.status(500).send(
            "something went wrong."
        );
    }
});


/*
 * delete your own post
 */

app.post(
    "/posts/:id/delete",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (!Number.isInteger(postId)) {
                return res.redirect(
                    req.get("referer") || "/feed"
                );
            }

            await db.prepare(`
                delete from posts
                where id = ?
                and user_id = ?
            `).run(
                postId,
                req.session.userId
            );

            res.redirect(
                req.get("referer") || "/feed"
            );
        } catch (error) {
            console.error(
                "delete post error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
 * like / unlike
 */

app.post(
    "/posts/:id/like",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (!Number.isInteger(postId)) {
                return res.redirect(
                    req.get("referer") || "/feed"
                );
            }

            const existing =
                await db.prepare(`
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
                    ) do nothing
                `).run(
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

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
 * comments
 */

app.get(
    "/posts/:id/comments",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (!Number.isInteger(postId)) {
                return res.status(404).send(
                    "post not found."
                );
            }

            const post =
                await db.prepare(`
                    select
                        posts.*,
                        users.username,
                        communities.name as community_name

                    from posts

                    join users
                        on users.id = posts.user_id

                    left join communities
                        on communities.id =
                            posts.community_id

                    where posts.id = ?
                `).get(postId);

            if (!post) {
                return res.status(404).send(
                    "post not found."
                );
            }

            const comments =
                await db.prepare(`
                    select
                        comments.id,
                        comments.content,
                        comments.created_at,
                        users.username

                    from comments

                    join users
                        on users.id =
                            comments.user_id

                    where comments.post_id = ?

                    order by comments.created_at asc
                `).all(postId);

            res.render("comments", {
                user: await currentUser(req),
                post,
                comments
            });
        } catch (error) {
            console.error(
                "comments page error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);

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

            const post =
                await db.prepare(`
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
                req.get("referer") ||
                `/posts/${postId}/comments`
            );
        } catch (error) {
            console.error(
                "comment error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
 * user profile
 */

app.get(
    "/u/:username",
    requireLogin,
    async (req, res) => {
        try {
            const username = String(
                req.params.username
            )
                .trim()
                .toLowerCase();

            const user =
                await db.prepare(`
                    select
                        id,
                        username,
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

            const posts =
                await db.prepare(`
                    select
                        posts.*,

                        (
                            select count(*)
                            from likes
                            where likes.post_id =
                                posts.id
                        ) as likes,

                        (
                            select count(*)
                            from comments
                            where comments.post_id =
                                posts.id
                        ) as comments

                    from posts

                    where posts.user_id = ?

                    order by posts.created_at desc
                `).all(user.id);

            const followers =
                await db.prepare(`
                    select count(*) as count
                    from follows
                    where following_id = ?
                `).get(user.id);

            const following =
                await db.prepare(`
                    select count(*) as count
                    from follows
                    where follower_id = ?
                `).get(user.id);

            const isFollowing =
                user.id !== req.session.userId &&
                !!(
                    await db.prepare(`
                        select id
                        from follows
                        where follower_id = ?
                        and following_id = ?
                    `).get(
                        req.session.userId,
                        user.id
                    )
                );

            res.render("profile", {
                user,
                posts,
                followers: followers.count,
                following: following.count,
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
                "something went wrong."
            );
        }
    }
);


/*
 * follow / unfollow
 */

app.post(
    "/u/:username/follow",
    requireLogin,
    async (req, res) => {
        try {
            const username = String(
                req.params.username
            )
                .trim()
                .toLowerCase();

            const target =
                await db.prepare(`
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

            const existing =
                await db.prepare(`
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
                    ) do nothing
                `).run(
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


/*
 * community page
 */

app.get(
    "/c/:name",
    requireLogin,
    async (req, res) => {
        try {
            const name = String(
                req.params.name || ""
            )
                .trim()
                .toLowerCase();

            const community =
                await db.prepare(`
                    select
                        id,
                        name,
                        description,
                        created_at

                    from communities

                    where name = ?
                `).get(name);

            if (!community) {
                return res.status(404).send(
                    "community not found."
                );
            }

            const posts =
                await db.prepare(`
                    select
                        posts.id,
                        posts.user_id,
                        posts.community_id,
                        posts.content,
                        posts.created_at,

                        users.username,

                        (
                            select count(*)
                            from likes
                            where likes.post_id =
                                posts.id
                        ) as likes,

                        (
                            select count(*)
                            from comments
                            where comments.post_id =
                                posts.id
                        ) as comments,

                        exists(
                            select 1
                            from likes
                            where likes.post_id =
                                posts.id

                            and likes.user_id = ?
                        ) as liked

                    from posts

                    join users
                        on users.id = posts.user_id

                    where posts.community_id = ?

                    order by posts.created_at desc

                    limit 100
                `).all(
                    req.session.userId,
                    community.id
                );

            const getComments =
                db.prepare(`
                    select
                        comments.id,
                        comments.content,
                        comments.created_at,
                        users.username

                    from comments

                    join users
                        on users.id =
                            comments.user_id

                    where comments.post_id = ?

                    order by comments.created_at asc
                `);

            for (const post of posts) {
                post.comment_list =
                    await getComments.all(
                        post.id
                    );
            }

            res.render("community", {
                community,
                posts,
                user: await currentUser(req)
            });
        } catch (error) {
            console.error(
                "community error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
 * admin login
 */

app.get(adminUrl, (req, res) => {
    if (req.session.admin) {
        return res.redirect(
            adminUrl + "/panel"
        );
    }

    res.render("admin-login", {
        error: null
    });
});

app.post(adminUrl, (req, res) => {
    const password = String(
        req.body.password || ""
    );

    if (password !== adminPassword) {
        return res.status(401).render(
            "admin-login",
            {
                error: "incorrect password."
            }
        );
    }

    req.session.admin = true;

    req.session.save(error => {
        if (error) {
            console.error(error);

            return res
                .status(500)
                .send("something went wrong.");
        }

        res.redirect(
            adminUrl + "/panel"
        );
    });
});


/*
 * admin panel
 */

app.get(
    adminUrl + "/panel",
    requireAdmin,
    async (req, res) => {
        try {
            const users =
                await db.prepare(`
                    select
                        users.id,
                        users.username,
                        users.bio,
                        users.created_at,

                        (
                            select count(*)
                            from posts
                            where posts.user_id =
                                users.id
                        ) as post_count

                    from users

                    order by users.created_at desc
                `).all();

            const posts =
                await db.prepare(`
                    select
                        posts.id,
                        posts.content,
                        posts.created_at,
                        users.username,
                        communities.name
                            as community_name

                    from posts

                    join users
                        on users.id = posts.user_id

                    left join communities
                        on communities.id =
                            posts.community_id

                    order by posts.created_at desc

                    limit 100
                `).all();

            const communities =
                await db.prepare(`
                    select
                        communities.id,
                        communities.name,
                        communities.description,
                        communities.created_at,

                        (
                            select count(*)
                            from posts
                            where posts.community_id =
                                communities.id
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
            console.error(
                "admin panel error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
 * admin logout
 */

app.post(
    adminUrl + "/logout",
    requireAdmin,
    (req, res) => {
        req.session.admin = false;

        req.session.save(error => {
            if (error) {
                console.error(error);
            }

            res.redirect(adminUrl);
        });
    }
);


/*
 * admin delete post
 */

app.post(
    adminUrl + "/posts/:id/delete",
    requireAdmin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (!Number.isInteger(postId)) {
                return res.redirect(
                    adminUrl + "/panel"
                );
            }

            await db.prepare(`
                delete from posts
                where id = ?
            `).run(postId);

            res.redirect(
                adminUrl + "/panel"
            );
        } catch (error) {
            console.error(
                "admin post delete error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
 * admin delete account
 */

app.post(
    adminUrl + "/users/:id/delete",
    requireAdmin,
    async (req, res) => {
        try {
            const userId = Number(
                req.params.id
            );

            if (!Number.isInteger(userId)) {
                return res.redirect(
                    adminUrl + "/panel"
                );
            }

            await db.prepare(`
                delete from users
                where id = ?
            `).run(userId);

            res.redirect(
                adminUrl + "/panel"
            );
        } catch (error) {
            console.error(
                "admin account delete error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
 * admin create community
 */

app.post(
    adminUrl + "/communities",
    requireAdmin,
    async (req, res) => {
        try {
            const name = String(
                req.body.name || ""
            )
                .trim()
                .toLowerCase();

            const description = String(
                req.body.description || ""
            ).trim();

            if (
                !/^[a-z0-9_-]{2,50}$/.test(name)
            ) {
                return res.redirect(
                    adminUrl + "/panel"
                );
            }

            if (description.length > 300) {
                return res.redirect(
                    adminUrl + "/panel"
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
                adminUrl + "/panel"
            );
        } catch (error) {
            console.error(
                "create community error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
 * admin delete community
 */

app.post(
    adminUrl + "/communities/:id/delete",
    requireAdmin,
    async (req, res) => {
        try {
            const communityId = Number(
                req.params.id
            );

            if (!Number.isInteger(communityId)) {
                return res.redirect(
                    adminUrl + "/panel"
                );
            }

            await db.prepare(`
                delete from communities
                where id = ?
            `).run(communityId);

            res.redirect(
                adminUrl + "/panel"
            );
        } catch (error) {
            console.error(
                "delete community error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);

app.post("/profile/customize", requireLogin, async (req, res) => {
    try {
        const bio = String(req.body.bio || "").trim();
        const displayName = String(req.body.display_name || "").trim();

        if (bio.length > 300) {
            return res.redirect(
                req.get("referer") || "/feed"
            );
        }

        if (displayName.length > 40) {
            return res.redirect(
                req.get("referer") || "/feed"
            );
        }

        await db.prepare(`
            update users
            set
                bio = ?,
                display_name = ?
            where id = ?
        `).run(
            bio,
            displayName,
            req.session.userId
        );

        res.redirect(
            "/u/" + req.body.username
        );

    } catch (error) {
        console.error(
            "profile customization error:",
            error
        );

        res.status(500).send(
            "something went wrong."
        );
    }
});

app.get("/posts/:id", requireLogin, async (req, res) => {
    try {
        const postId = Number(req.params.id);

        if (!Number.isInteger(postId)) {
            return res.status(404).send(
                "post not found."
            );
        }

        const post = await db.prepare(`
            select
                posts.id,
                posts.user_id,
                posts.community_id,
                posts.content,
                posts.created_at,

                users.username,
                users.display_name,

                communities.name as community_name,

                (
                    select count(*)
                    from likes
                    where likes.post_id = posts.id
                ) as likes,

                exists(
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

            where posts.id = ?
        `).get(
            req.session.userId,
            postId
        );

        if (!post) {
            return res.status(404).send(
                "post not found."
            );
        }

        const comments = await db.prepare(`
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
        `).all(postId);

        res.render("post", {
            post,
            comments,
            user: await currentUser(req)
        });

    } catch (error) {
        console.error(
            "post page error:",
            error
        );

        res.status(500).send(
            "something went wrong."
        );
    }
});

/*
 * 404
 */

app.use((req, res) => {
    res.status(404).send(
        "page not found."
    );
});


/*
 * startup
 */

async function start() {
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

start();
