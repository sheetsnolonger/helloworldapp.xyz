require("dotenv").config();

const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("./database");

const app = express();

const port = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";

if (
    isProduction &&
    (
        !process.env.SESSION_SECRET ||
        process.env.SESSION_SECRET.length < 32
    )
) {
    throw new Error(
        "SESSION_SECRET must be set to a long random value in production."
    );
}

const adminPath =
    process.env.ADMIN_PATH ||
    "xkqvmtzplrjwhsne";

const adminPassword =
    process.env.ADMIN_PASSWORD ||
    "";

if (isProduction && !adminPassword) {
    console.warn(
        "warning: ADMIN_PASSWORD is not set."
    );
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.set("trust proxy", 1);

app.use(
    express.urlencoded({
        extended: false,
        limit: "20kb"
    })
);

app.use(
    express.json({
        limit: "20kb"
    })
);

app.use(
    session({
        store: new pgSession({
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
            maxAge:
                1000 *
                60 *
                60 *
                24 *
                30
        }
    })
);

app.use(
    express.static(
        path.join(__dirname, "public"),
        {
            maxAge:
                isProduction
                    ? "7d"
                    : 0
        }
    )
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

function getAdminSession(req) {
    return Boolean(req.session.adminAuthenticated);
}

function requireAdmin(req, res, next) {
    if (!getAdminSession(req)) {
        return res.redirect("/" + adminPath);
    }

    next();
}


/*
|--------------------------------------------------------------------------
| health
|--------------------------------------------------------------------------
*/

app.get("/health", async (req, res) => {
    try {
        await db.pool.query("select 1");

        res.status(200).json({
            status: "ok",
            service: "helloworld",
            database: "ok"
        });

    } catch (error) {
        console.error(
            "health check failed:",
            error
        );

        res.status(500).json({
            status: "error",
            service: "helloworld",
            database: "error"
        });
    }
});


/*
|--------------------------------------------------------------------------
| home
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/feed");
    }

    res.render("index");
});


/*
|--------------------------------------------------------------------------
| register
|--------------------------------------------------------------------------
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

        const hash =
            await bcrypt.hash(
                password,
                12
            );

        const result =
            await db.prepare(`
                insert into users
                    (
                        username,
                        display_name,
                        password
                    )
                values
                    (?, ?, ?)
                returning id
            `).run(
                username,
                "",
                hash
            );

        const userId =
            result.lastInsertRowid;

        req.session.regenerate(error => {
            if (error) {
                console.error(error);

                return res
                    .status(500)
                    .send(
                        "something went wrong."
                    );
            }

            req.session.userId =
                userId;

            req.session.save(error => {
                if (error) {
                    console.error(error);

                    return res
                        .status(500)
                        .send(
                            "something went wrong."
                        );
                }

                res.redirect("/feed");
            });
        });

    } catch (error) {
        console.error(
            "register error:",
            error
        );

        res.status(500).send(
            "something went wrong."
        );
    }
});


/*
|--------------------------------------------------------------------------
| login
|--------------------------------------------------------------------------
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

        const user =
            await db.prepare(`
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

        const valid =
            await bcrypt.compare(
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
                    .send(
                        "something went wrong."
                    );
            }

            req.session.userId =
                user.id;

            req.session.save(error => {
                if (error) {
                    console.error(error);

                    return res
                        .status(500)
                        .send(
                            "something went wrong."
                        );
                }

                res.redirect("/feed");
            });
        });

    } catch (error) {
        console.error(
            "login error:",
            error
        );

        res.status(500).send(
            "something went wrong."
        );
    }
});


/*
|--------------------------------------------------------------------------
| logout
|--------------------------------------------------------------------------
*/

app.post(
    "/logout",
    requireLogin,
    (req, res) => {
        req.session.destroy(error => {
            if (error) {
                console.error(error);
            }

            res.clearCookie(
                "connect.sid"
            );

            res.redirect("/");
        });
    }
);


/*
|--------------------------------------------------------------------------
| feed
|--------------------------------------------------------------------------
*/

app.get(
    "/feed",
    requireLogin,
    async (req, res) => {
        try {
            const user =
                await currentUser(req);

            if (!user) {
                return res.redirect(
                    "/login"
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
                        users.display_name,

                        communities.name
                            as community_name,

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
                        on users.id =
                            posts.user_id

                    left join communities
                        on communities.id =
                            posts.community_id

                    order by
                        posts.created_at desc

                    limit 100
                `).all(user.id);


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

                    order by
                        communities.created_at desc
                `).all();


            res.render("feed", {
                user,
                posts,
                communities
            });

        } catch (error) {
            console.error(
                "feed error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
|--------------------------------------------------------------------------
| create post
|--------------------------------------------------------------------------
*/

app.post(
    "/posts",
    requireLogin,
    async (req, res) => {
        try {
            const content = String(
                req.body.content || ""
            ).trim();

            const communityId =
                req.body.community_id
                    ? Number(
                        req.body.community_id
                    )
                    : null;


            if (
                !content ||
                content.length > 500
            ) {
                return res.redirect(
                    "/feed"
                );
            }


            if (
                communityId !== null &&
                !Number.isInteger(
                    communityId
                )
            ) {
                return res.redirect(
                    "/feed"
                );
            }


            if (communityId !== null) {
                const community =
                    await db.prepare(`
                        select id
                        from communities
                        where id = ?
                    `).get(
                        communityId
                    );

                if (!community) {
                    return res.redirect(
                        "/feed"
                    );
                }
            }


            await db.prepare(`
                insert into posts
                    (
                        user_id,
                        community_id,
                        content
                    )
                values
                    (?, ?, ?)
            `).run(
                req.session.userId,
                communityId,
                content
            );


            res.redirect("/feed");

        } catch (error) {
            console.error(
                "create post error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
|--------------------------------------------------------------------------
| individual post
|--------------------------------------------------------------------------
*/

app.get(
    "/posts/:id",
    requireLogin,
    async (req, res) => {
        try {
            const postId =
                Number(req.params.id);

            if (
                !Number.isInteger(
                    postId
                )
            ) {
                return res.status(404).send(
                    "post not found."
                );
            }


            const post =
                await db.prepare(`
                    select
                        posts.id,
                        posts.user_id,
                        posts.community_id,
                        posts.content,
                        posts.created_at,

                        users.username,
                        users.display_name,

                        communities.name
                            as community_name,

                        (
                            select count(*)
                            from likes
                            where likes.post_id =
                                posts.id
                        ) as likes,

                        exists(
                            select 1
                            from likes
                            where likes.post_id =
                                posts.id
                            and likes.user_id = ?
                        ) as liked

                    from posts

                    join users
                        on users.id =
                            posts.user_id

                    left join communities
                        on communities.id =
                            posts.community_id

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


            const comments =
                await db.prepare(`
                    select
                        comments.id,
                        comments.content,
                        comments.created_at,

                        users.username,
                        users.display_name

                    from comments

                    join users
                        on users.id =
                            comments.user_id

                    where comments.post_id = ?

                    order by
                        comments.created_at asc
                `).all(postId);


            const user =
                await currentUser(req);


            res.render("post", {
                post,
                comments,
                user
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
    }
);


/*
|--------------------------------------------------------------------------
| like post
|--------------------------------------------------------------------------
*/

app.post(
    "/posts/:id/like",
    requireLogin,
    async (req, res) => {
        try {
            const postId =
                Number(req.params.id);

            if (
                !Number.isInteger(
                    postId
                )
            ) {
                return res.redirect(
                    req.get("referer") ||
                    "/feed"
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
                `).run(
                    existing.id
                );

            } else {

                await db.prepare(`
                    insert into likes
                        (
                            user_id,
                            post_id
                        )
                    values
                        (?, ?)
                    on conflict
                        (user_id, post_id)
                    do nothing
                `).run(
                    req.session.userId,
                    postId
                );
            }


            res.redirect(
                req.get("referer") ||
                "/feed"
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
|--------------------------------------------------------------------------
| comments
|--------------------------------------------------------------------------
*/

app.get("/posts/:id/comments", requireLogin, async (req, res) => {
    try {
        const postId = Number(req.params.id);

        if (!Number.isInteger(postId)) {
            return res.status(404).send("post not found.");
        }

        const post = await db.prepare(`
            select
                posts.*,
                users.username,
                (
                    select count(*)
                    from likes
                    where likes.post_id = posts.id
                ) as likes
            from posts
            join users on users.id = posts.user_id
            where posts.id = ?
        `).get(postId);

        if (!post) {
            return res.status(404).send("post not found.");
        }

        const comments = await db.prepare(`
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

        const user = currentUser(req);

        res.render("comments", {
            user,
            post,
            comments
        });
    } catch (error) {
        console.error("comments page error:", error);
        res.status(500).send("internal server error.");
    }
});

app.post("/posts/:id/comments", requireLogin, async (req, res) => {
    try {
        const postId = Number(req.params.id);
        const content = String(req.body.content || "").trim();

        if (
            !Number.isInteger(postId) ||
            !content ||
            content.length > 300
        ) {
            return res.redirect(`/posts/${postId}/comments`);
        }

        const post = await db.prepare(
            "select id from posts where id = ?"
        ).get(postId);

        if (!post) {
            return res.status(404).send("post not found.");
        }

        await db.prepare(`
            insert into comments
                (user_id, post_id, content)
            values
                (?, ?, ?)
        `).run(
            req.session.userId,
            postId,
            content
        );

        res.redirect(`/posts/${postId}/comments`);
    } catch (error) {
        console.error("comment error:", error);
        res.status(500).send("internal server error.");
    }
});
/*
|--------------------------------------------------------------------------
| delete own post
|--------------------------------------------------------------------------
*/

app.post(
    "/posts/:id/delete",
    requireLogin,
    async (req, res) => {
        try {
            const postId =
                Number(req.params.id);

            if (
                !Number.isInteger(
                    postId
                )
            ) {
                return res.redirect(
                    "/feed"
                );
            }


            const post =
                await db.prepare(`
                    select
                        id,
                        user_id
                    from posts
                    where id = ?
                `).get(postId);


            if (!post) {
                return res.redirect(
                    "/feed"
                );
            }


            if (
                Number(post.user_id) !==
                Number(req.session.userId)
            ) {
                return res.status(403).send(
                    "you can only delete your own posts."
                );
            }


            await db.prepare(`
                delete from posts
                where id = ?
            `).run(postId);


            res.redirect(
                req.get("referer") ||
                "/feed"
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
|--------------------------------------------------------------------------
| profile
|--------------------------------------------------------------------------
*/

app.get(
    "/u/:username",
    requireLogin,
    async (req, res) => {
        try {
            const username =
                String(
                    req.params.username ||
                    ""
                )
                    .trim()
                    .toLowerCase();


            const user =
                await db.prepare(`
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


            const posts =
                await db.prepare(`
                    select
                        posts.id,
                        posts.user_id,
                        posts.community_id,
                        posts.content,
                        posts.created_at,

                        communities.name
                            as community_name,

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

                    left join communities
                        on communities.id =
                            posts.community_id

                    where posts.user_id = ?

                    order by
                        posts.created_at desc
                `).all(user.id);


            const followersResult =
                await db.prepare(`
                    select count(*) as count
                    from follows
                    where following_id = ?
                `).get(user.id);


            const followingResult =
                await db.prepare(`
                    select count(*) as count
                    from follows
                    where follower_id = ?
                `).get(user.id);


            const following =
                Number(
                    followingResult?.count ||
                    0
                );


            const followers =
                Number(
                    followersResult?.count ||
                    0
                );


            let isFollowing = false;


            if (
                Number(user.id) !==
                Number(req.session.userId)
            ) {
                const follow =
                    await db.prepare(`
                        select id
                        from follows
                        where follower_id = ?
                        and following_id = ?
                    `).get(
                        req.session.userId,
                        user.id
                    );

                isFollowing =
                    Boolean(follow);
            }


            const loggedInUser =
                await currentUser(req);


            res.render("profile", {
                user,
                posts,
                followers,
                following,
                isFollowing,
                currentUser:
                    loggedInUser
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
|--------------------------------------------------------------------------
| profile customization
|--------------------------------------------------------------------------
*/

app.post(
    "/profile/customize",
    requireLogin,
    async (req, res) => {
        try {
            const bio =
                String(
                    req.body.bio || ""
                ).trim();

            const displayName =
                String(
                    req.body.display_name ||
                    ""
                ).trim();


            if (bio.length > 300) {
                return res.redirect(
                    req.get("referer") ||
                    "/feed"
                );
            }


            if (
                displayName.length > 40
            ) {
                return res.redirect(
                    req.get("referer") ||
                    "/feed"
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


            const username =
                String(
                    req.body.username ||
                    ""
                )
                    .trim()
                    .toLowerCase();


            res.redirect(
                "/u/" + username
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
    }
);


/*
|--------------------------------------------------------------------------
| follow
|--------------------------------------------------------------------------
*/

app.post(
    "/u/:username/follow",
    requireLogin,
    async (req, res) => {
        try {
            const username =
                String(
                    req.params.username ||
                    ""
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
                Number(target.id) ===
                Number(req.session.userId)
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
                `).run(
                    existing.id
                );

            } else {

                await db.prepare(`
                    insert into follows
                        (
                            follower_id,
                            following_id
                        )
                    values
                        (?, ?)
                    on conflict
                        (
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
|--------------------------------------------------------------------------
| community page
|--------------------------------------------------------------------------
*/

app.get(
    "/c/:name",
    requireLogin,
    async (req, res) => {
        try {
            const name =
                String(
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


            const user =
                await currentUser(req);


            const posts =
                await db.prepare(`
                    select
                        posts.id,
                        posts.user_id,
                        posts.community_id,
                        posts.content,
                        posts.created_at,

                        users.username,
                        users.display_name,

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
                        on users.id =
                            posts.user_id

                    where posts.community_id = ?

                    order by
                        posts.created_at desc

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

                        users.username,
                        users.display_name

                    from comments

                    join users
                        on users.id =
                            comments.user_id

                    where comments.post_id = ?

                    order by
                        comments.created_at asc
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
                user
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
|--------------------------------------------------------------------------
| admin login
|--------------------------------------------------------------------------
*/

app.get(
    "/" + adminPath,
    (req, res) => {

        if (req.session.adminAuthenticated) {
            return res.redirect(
                "/" + adminPath + "/panel"
            );
        }

        res.render(
            "admin-login",
            {
                error: null
            }
        );
    }
);


app.post(
    "/" + adminPath,
    async (req, res) => {

        const password =
            String(
                req.body.password || ""
            );


        if (
            !adminPassword ||
            password !== adminPassword
        ) {
            return res.render(
                "admin-login",
                {
                    error:
                        "incorrect password."
                }
            );
        }


        req.session.adminAuthenticated =
            true;


        req.session.save(error => {

            if (error) {
                console.error(error);

                return res
                    .status(500)
                    .send(
                        "something went wrong."
                    );
            }


            res.redirect(
                "/" + adminPath + "/panel"
            );
        });
    }
);


/*
|--------------------------------------------------------------------------
| admin panel
|--------------------------------------------------------------------------
*/

app.get(
    "/" + adminPath + "/panel",
    requireAdmin,
    async (req, res) => {

        try {

            const users =
                await db.prepare(`
                    select
                        id,
                        username,
                        display_name,
                        bio,
                        created_at
                    from users
                    order by
                        created_at desc
                    limit 500
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
                        on users.id =
                            posts.user_id

                    left join communities
                        on communities.id =
                            posts.community_id

                    order by
                        posts.created_at desc

                    limit 500
                `).all();


            const communities =
                await db.prepare(`
                    select
                        communities.id,
                        communities.name,
                        communities.description,
                        communities.created_at
                    from communities
                    order by
                        communities.created_at desc
                `).all();


            res.render(
                "admin",
                {
                    users,
                    posts,
                    communities
                }
            );

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
|--------------------------------------------------------------------------
| admin delete post
|--------------------------------------------------------------------------
*/

app.post(
    "/" + adminPath + "/posts/:id/delete",
    requireAdmin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);


            if (
                !Number.isInteger(id)
            ) {
                return res.redirect(
                    "/" +
                    adminPath +
                    "/panel"
                );
            }


            await db.prepare(`
                delete from posts
                where id = ?
            `).run(id);


            res.redirect(
                "/" +
                adminPath +
                "/panel"
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


/*
|--------------------------------------------------------------------------
| admin delete account
|--------------------------------------------------------------------------
*/

app.post(
    "/" + adminPath + "/users/:id/delete",
    requireAdmin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);


            if (
                !Number.isInteger(id)
            ) {
                return res.redirect(
                    "/" +
                    adminPath +
                    "/panel"
                );
            }


            await db.prepare(`
                delete from users
                where id = ?
            `).run(id);


            res.redirect(
                "/" +
                adminPath +
                "/panel"
            );

        } catch (error) {

            console.error(
                "admin user deletion error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
|--------------------------------------------------------------------------
| admin create community
|--------------------------------------------------------------------------
*/

app.post(
    "/" + adminPath + "/communities",
    requireAdmin,
    async (req, res) => {

        try {

            const name =
                String(
                    req.body.name || ""
                )
                    .trim()
                    .toLowerCase();

            const description =
                String(
                    req.body.description ||
                    ""
                ).trim();


            if (
                !/^[a-z0-9_-]{2,40}$/.test(
                    name
                )
            ) {
                return res.redirect(
                    "/" +
                    adminPath +
                    "/panel"
                );
            }


            if (
                description.length > 500
            ) {
                return res.redirect(
                    "/" +
                    adminPath +
                    "/panel"
                );
            }


            await db.prepare(`
                insert into communities
                    (
                        name,
                        description
                    )
                values
                    (?, ?)
                on conflict (name)
                do nothing
            `).run(
                name,
                description
            );


            res.redirect(
                "/" +
                adminPath +
                "/panel"
            );

        } catch (error) {

            console.error(
                "community creation error:",
                error
            );

            res.status(500).send(
                "something went wrong."
            );
        }
    }
);


/*
|--------------------------------------------------------------------------
| admin delete community
|--------------------------------------------------------------------------
*/

app.post(
    "/" + adminPath + "/communities/:id/delete",
    requireAdmin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);


            if (
                !Number.isInteger(id)
            ) {
                return res.redirect(
                    "/" +
                    adminPath +
                    "/panel"
                );
            }


            await db.prepare(`
                update posts
                set community_id = null
                where community_id = ?
            `).run(id);


            await db.prepare(`
                delete from communities
                where id = ?
            `).run(id);


            res.redirect(
                "/" +
                adminPath +
                "/panel"
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


/*
|--------------------------------------------------------------------------
| admin logout
|--------------------------------------------------------------------------
*/

app.post(
    "/" + adminPath + "/logout",
    requireAdmin,
    (req, res) => {

        req.session.adminAuthenticated =
            false;

        req.session.save(() => {
            res.redirect(
                "/" + adminPath
            );
        });
    }
);


/*
|--------------------------------------------------------------------------
| 404
|--------------------------------------------------------------------------
*/

app.use(
    (req, res) => {
        res.status(404).send(
            "page not found."
        );
    }
);


/*
|--------------------------------------------------------------------------
| startup
|--------------------------------------------------------------------------
*/

async function startServer() {

    try {

        await db.initializeDatabase();

        app.listen(
            port,
            () => {
                console.log(
                    "helloworld is running on port " +
                    port
                );
            }
        );

    } catch (error) {

        console.error(
            "failed to start server:"
        );

        console.error(error);

        process.exit(1);
    }
}

startServer();
