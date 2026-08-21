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

const adminPath =
    process.env.ADMIN_PATH ||
    "m7qzv2k9x4p8n3r6";

const adminPassword =
    process.env.ADMIN_PASSWORD ||
    "SamanthaVT*374-SJpa";

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
            createTableIfMissing: false
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
            maxAge: isProduction
                ? "7d"
                : 0
        }
    )
);

app.locals.formatDate = function (date) {
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
        return res.redirect(
            `/admin/${adminPath}/login`
        );
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
            display_name,
            created_at
        from users
        where id = ?
    `).get(req.session.userId);
}

async function getPostComments(postId) {
    return db.prepare(`
        select
            comments.id,
            comments.content,
            comments.created_at,
            users.id as user_id,
            users.username,
            users.display_name
        from comments
        join users
            on users.id = comments.user_id
        where comments.post_id = ?
        order by comments.created_at asc
    `).all(postId);
}

async function getPost(postId, userId) {
    return db.prepare(`
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

        where posts.id = ?
    `).get(userId, postId);
}

/* health */

app.get("/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        service: "helloworld"
    });
});

/* home */

app.get("/", async (req, res) => {
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
    const username = String(
        req.body.username || ""
    )
        .trim()
        .toLowerCase();

    const password = String(
        req.body.password || ""
    );

    if (
        !/^[a-z0-9_]{3,30}$/.test(
            username
        )
    ) {
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
        insert into users
            (username, password)
        values
            (?, ?)
        returning id
    `).run(username, hash);

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
});

/* logout */

app.post(
    "/logout",
    requireLogin,
    (req, res) => {
        req.session.destroy(() => {
            res.clearCookie(
                "connect.sid"
            );

            res.redirect("/");
        });
    }
);

/* feed */

app.get(
    "/feed",
    requireLogin,
    async (req, res) => {
        try {
            const user =
                await currentUser(req);

            const posts =
                await db.prepare(`
                    select
                        posts.*,

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

                        exists (
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

                    where
                        posts.user_id = ?

                        or posts.user_id in (
                            select following_id
                            from follows
                            where follower_id = ?
                        )

                        or posts.community_id in (
                            select id
                            from communities
                        )

                    order by
                        posts.created_at desc

                    limit 100
                `).all(
                    req.session.userId,
                    req.session.userId,
                    req.session.userId
                );

            for (const post of posts) {
                post.comment_list =
                    await getPostComments(
                        post.id
                    );
            }

            const communities =
                await db.prepare(`
                    select
                        id,
                        name,
                        description,
                        created_at
                    from communities
                    order by name asc
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

            res
                .status(500)
                .send(
                    "internal server error while loading the feed."
                );
        }
    }
);

/* create post */

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
                          req.body
                              .community_id
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

            let validCommunity = null;

            if (
                communityId &&
                Number.isInteger(
                    communityId
                )
            ) {
                validCommunity =
                    await db.prepare(`
                        select id
                        from communities
                        where id = ?
                    `).get(communityId);
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
                validCommunity
                    ? validCommunity.id
                    : null,
                content
            );

            res.redirect("/feed");
        } catch (error) {
            console.error(
                "create post error:",
                error
            );

            res
                .status(500)
                .send(
                    "something went wrong."
                );
        }
    }
);

/* individual post */

app.get(
    "/posts/:id",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (
                !Number.isInteger(
                    postId
                )
            ) {
                return res
                    .status(404)
                    .send(
                        "post not found."
                    );
            }

            const post =
                await getPost(
                    postId,
                    req.session.userId
                );

            if (!post) {
                return res
                    .status(404)
                    .send(
                        "post not found."
                    );
            }

            post.comment_list =
                await getPostComments(
                    post.id
                );

            const user =
                await currentUser(req);

            res.render("comments", {
                user,
                post
            });
        } catch (error) {
            console.error(
                "post page error:",
                error
            );

            res
                .status(500)
                .send(
                    "internal server error while viewing this post."
                );
        }
    }
);

/* likes */

app.post(
    "/posts/:id/like",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (
                !Number.isInteger(
                    postId
                )
            ) {
                return res.redirect(
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
                `).run(existing.id);
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

            res.redirect("/feed");
        }
    }
);

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
                !Number.isInteger(
                    postId
                ) ||
                !content ||
                content.length > 300
            ) {
                return res.redirect(
                    `/posts/${postId}`
                );
            }

            const post =
                await db.prepare(`
                    select id
                    from posts
                    where id = ?
                `).get(postId);

            if (!post) {
                return res
                    .status(404)
                    .send(
                        "post not found."
                    );
            }

            await db.prepare(`
                insert into comments
                    (
                        user_id,
                        post_id,
                        content
                    )
                values
                    (?, ?, ?)
            `).run(
                req.session.userId,
                postId,
                content
            );

            res.redirect(
                `/posts/${postId}`
            );
        } catch (error) {
            console.error(
                "comment error:",
                error
            );

            res
                .status(500)
                .send(
                    "something went wrong while posting your comment."
                );
        }
    }
);

/* delete own post */

app.post(
    "/posts/:id/delete",
    requireLogin,
    async (req, res) => {
        try {
            const postId = Number(
                req.params.id
            );

            if (
                !Number.isInteger(
                    postId
                )
            ) {
                return res.redirect(
                    "/feed"
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
                req.get("referer") ||
                    "/feed"
            );
        } catch (error) {
            console.error(
                "delete post error:",
                error
            );

            res.redirect("/feed");
        }
    }
);

/* profiles */

app.get(
    "/u/:username",
    requireLogin,
    async (req, res) => {
        try {
            const username =
                String(
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
                        display_name,
                        created_at
                    from users
                    where username = ?
                `).get(username);

            if (!user) {
                return res
                    .status(404)
                    .send(
                        "user not found."
                    );
            }

            const posts =
                await db.prepare(`
                    select
                        posts.id,
                        posts.user_id,
                        posts.content,
                        posts.created_at,
                        posts.community_id,

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
                user.id !==
                    req.session.userId &&
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
                followers:
                    followers.count,
                following:
                    following.count,
                isFollowing,
                currentUser:
                    await currentUser(
                        req
                    )
            });
        } catch (error) {
            console.error(
                "profile error:",
                error
            );

            res
                .status(500)
                .send(
                    "internal server error while viewing this profile."
                );
        }
    }
);

/* edit profile */

app.get(
    "/settings/profile",
    requireLogin,
    async (req, res) => {
        const user =
            await currentUser(req);

        res.render(
            "profile-settings",
            {
                user,
                error: null
            }
        );
    }
);

app.post(
    "/settings/profile",
    requireLogin,
    async (req, res) => {
        try {
            const displayName =
                String(
                    req.body.display_name ||
                        ""
                )
                    .trim()
                    .slice(0, 40);

            const bio =
                String(
                    req.body.bio || ""
                )
                    .trim()
                    .slice(0, 500);

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

            res.redirect(
                `/u/${
                    (
                        await currentUser(
                            req
                        )
                    ).username
                }`
            );
        } catch (error) {
            console.error(
                "profile update error:",
                error
            );

            res
                .status(500)
                .send(
                    "something went wrong."
                );
        }
    }
);

/* follow */

app.post(
    "/u/:username/follow",
    requireLogin,
    async (req, res) => {
        const username =
            String(
                req.params.username
            ).toLowerCase();

        const target =
            await db.prepare(`
                select id
                from users
                where username = ?
            `).get(username);

        if (
            !target ||
            target.id ===
                req.session.userId
        ) {
            return res.redirect(
                `/u/${username}`
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
            `/u/${username}`
        );
    }
);


/* admin login */

app.get(
    `/admin/${adminPath}/login`,
    (req, res) => {
        if (req.session.admin) {
            return res.redirect(
                `/admin/${adminPath}`
            );
        }

        res.render("admin-login", {
            error: null
        });
    }
);

app.post(
    `/admin/${adminPath}/login`,
    (req, res) => {
        const password = String(
            req.body.password || ""
        );

        if (
            password !==
            adminPassword
        ) {
            return res.render(
                "admin-login",
                {
                    error:
                        "incorrect password."
                }
            );
        }

        req.session.admin = true;

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
                `/admin/${adminPath}`
            );
        });
    }
);

/* admin panel */

app.get(
    `/admin/${adminPath}`,
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
                `).all();

            const posts =
                await db.prepare(`
                    select
                        posts.id,
                        posts.content,
                        posts.created_at,
                        users.username
                    from posts
                    join users
                        on users.id =
                            posts.user_id
                    order by
                        posts.created_at desc
                `).all();

            const communities =
                await db.prepare(`
                    select
                        id,
                        name,
                        description,
                        created_at
                    from communities
                    order by name asc
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
                "admin error:",
                error
            );

            res
                .status(500)
                .send(
                    "internal server error while loading admin panel."
                );
        }
    }
);

/* admin delete post */

app.post(
    `/admin/${adminPath}/posts/:id/delete`,
    requireAdmin,
    async (req, res) => {
        await db.prepare(`
            delete from posts
            where id = ?
        `).run(
            Number(req.params.id)
        );

        res.redirect(
            `/admin/${adminPath}`
        );
    }
);

/* admin delete account */

app.post(
    `/admin/${adminPath}/users/:id/delete`,
    requireAdmin,
    async (req, res) => {
        await db.prepare(`
            delete from users
            where id = ?
        `).run(
            Number(req.params.id)
        );

        res.redirect(
            `/admin/${adminPath}`
        );
    }
);

/* admin create community */

app.post(
    `/admin/${adminPath}/communities`,
    requireAdmin,
    async (req, res) => {
        try {
            const name = String(
                req.body.name || ""
            )
                .trim()
                .toLowerCase()
                .slice(0, 50);

            const description =
                String(
                    req.body.description ||
                        ""
                )
                    .trim()
                    .slice(0, 300);

            if (!name) {
                return res.redirect(
                    `/admin/${adminPath}`
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
                `/admin/${adminPath}`
            );
        } catch (error) {
            console.error(
                "community creation error:",
                error
            );

            res
                .status(500)
                .send(
                    "could not create community."
                );
        }
    }
);

/* admin delete community */

app.post(
    `/admin/${adminPath}/communities/:id/delete`,
    requireAdmin,
    async (req, res) => {
        await db.prepare(`
            delete from communities
            where id = ?
        `).run(
            Number(req.params.id)
        );

        res.redirect(
            `/admin/${adminPath}`
        );
    }
);

/* admin logout */

app.post(
    `/admin/${adminPath}/logout`,
    requireAdmin,
    (req, res) => {
        req.session.admin = false;

        req.session.save(() => {
            res.redirect(
                `/admin/${adminPath}/login`
            );
        });
    }
);

app.get("/communities", requireLogin, async (req, res) => {
    try {
        const communities = await db.prepare(`
            select
                communities.id,
                communities.name,
                communities.description,
                communities.created_at,
                count(posts.id)::integer as post_count
            from communities
            left join posts
                on posts.community_id = communities.id
            group by
                communities.id,
                communities.name,
                communities.description,
                communities.created_at
            order by communities.name asc
        `).all();

        res.render("communities", {
            user: currentUser(req),
            communities
        });
    } catch (error) {
        console.error("communities page error:", error);
        res.status(500).send("internal server error.");
    }
});


app.get("/community/:id", requireLogin, async (req, res) => {
    try {
        const communityId = Number(req.params.id);

        if (!Number.isInteger(communityId)) {
            return res.status(404).send("community not found.");
        }

        const community = await db.prepare(`
            select
                id,
                name,
                description,
                created_at
            from communities
            where id = ?
        `).get(communityId);

        if (!community) {
            return res.status(404).send("community not found.");
        }

        const user = currentUser(req);

        const posts = await db.prepare(`
            select
                posts.id,
                posts.content,
                posts.created_at,
                posts.user_id,
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
            where posts.community_id = ?
            order by posts.created_at desc
            limit 100
        `).all(req.session.userId, communityId);

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
            post.comment_list = await getComments.all(post.id);
        }

        res.render("community", {
            user,
            community,
            posts
        });
    } catch (error) {
        console.error("community page error:", error);
        res.status(500).send("internal server error.");
    }
});


app.post("/community/:id/posts", requireLogin, async (req, res) => {
    try {
        const communityId = Number(req.params.id);
        const content = String(req.body.content || "").trim();

        if (!Number.isInteger(communityId)) {
            return res.status(404).send("community not found.");
        }

        if (!content || content.length > 500) {
            return res.redirect(`/community/${communityId}`);
        }

        const community = await db.prepare(`
            select id
            from communities
            where id = ?
        `).get(communityId);

        if (!community) {
            return res.status(404).send("community not found.");
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

        res.redirect(`/community/${communityId}`);
    } catch (error) {
        console.error("community post error:", error);
        res.status(500).send("internal server error.");
    }
});

/* 404 */

app.use((req, res) => {
    res.status(404).send(
        "page not found."
    );
});

/* error handler */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {
        console.error(
            "unhandled server error:",
            error
        );

        if (res.headersSent) {
            return next(error);
        }

        res.status(500).send(
            "internal server error."
        );
    }
);

/* start */

async function start() {
    try {
        await db.initializeDatabase();

        app.listen(
            port,
            "0.0.0.0",
            () => {
                console.log(
                    "helloworld is running on port " +
                        port
                );

                console.log(
                    "database: postgresql"
                );
            }
        );
    } catch (error) {
        console.error(
            "failed to start helloworld:"
        );

        console.error(error);

        process.exit(1);
    }
}

start();
