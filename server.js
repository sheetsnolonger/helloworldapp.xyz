require("dotenv").config();

const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const port = process.env.PORT || 3000;


/* =========================================================
   database
   ========================================================= */

if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is missing");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    },

    max: 10,

    idleTimeoutMillis: 30000,

    connectionTimeoutMillis: 10000
});

pool.on("error", (error) => {
    console.error("unexpected database error:");
    console.error(error);
});


/* =========================================================
   supabase
   ========================================================= */

let supabase = null;

if (
    process.env.SUPABASE_URL &&
    process.env.SUPABASE_SERVICE_ROLE_KEY
) {
    supabase = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    console.log("supabase storage enabled");
} else {
    console.log("supabase storage disabled");
}

const storage_bucket =
    process.env.SUPABASE_STORAGE_BUCKET || "uploads";


/* =========================================================
   app configuration
   ========================================================= */

app.set("view engine", "ejs");

app.set(
    "views",
    path.join(__dirname, "views")
);

app.disable("x-powered-by");

app.use(express.urlencoded({
    extended: true
}));

app.use(express.json());

app.use(express.static(
    path.join(__dirname, "public")
));


/* =========================================================
   local uploads
   ========================================================= */

const upload_directory = path.join(
    __dirname,
    "uploads"
);

if (!fs.existsSync(upload_directory)) {
    fs.mkdirSync(upload_directory, {
        recursive: true
    });
}

app.use(
    "/uploads",
    express.static(upload_directory)
);


/* =========================================================
   multer
   ========================================================= */

const upload = multer({
    storage: multer.memoryStorage(),

    limits: {
        fileSize: 15 * 1024 * 1024
    },

    fileFilter: (req, file, callback) => {

        const allowed = [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp"
        ];

        if (!allowed.includes(file.mimetype)) {
            return callback(
                new Error("only image files are allowed")
            );
        }

        callback(null, true);
    }
});


/* =========================================================
   sessions
   ========================================================= */

app.use(
    session({
        store: new pgSession({
            pool: pool,

            tableName: "user_sessions",

            createTableIfMissing: true
        }),

        secret:
            process.env.SESSION_SECRET ||
            "helloworld-change-this-session-secret",

        resave: false,

        saveUninitialized: false,

        cookie: {
            maxAge:
                1000 *
                60 *
                60 *
                24 *
                30,

            httpOnly: true,

            secure:
                process.env.NODE_ENV === "production",

            sameSite: "lax"
        }
    })
);


/* =========================================================
   helpers
   ========================================================= */

function requireLogin(req, res, next) {

    if (!req.user) {
        return res.redirect("/login");
    }

    next();
}


function requireAdmin(req, res, next) {

    if (!req.user) {
        return res.redirect("/login");
    }

    if (!req.user.is_admin) {
        return res.status(403).send(
            "you do not have permission to access this page"
        );
    }

    next();
}


function formatDate(date) {

    if (!date) {
        return "";
    }

    return new Date(date).toLocaleString(
        "en-US",
        {
            month: "short",
            day: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "2-digit"
        }
    );
}


async function uploadToSupabase(file, folder) {

    if (!file) {
        return null;
    }

    /*
     * if supabase isn't configured, save locally.
     * this prevents the application from crashing just
     * because storage isn't configured yet.
     */

    if (!supabase) {

        const extension =
            path.extname(
                file.originalname
            ) || ".jpg";

        const filename =
            `${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}${extension}`;

        const local_path =
            path.join(
                upload_directory,
                filename
            );

        fs.writeFileSync(
            local_path,
            file.buffer
        );

        return `/uploads/${filename}`;
    }


    const extension =
        path.extname(
            file.originalname
        ) || ".jpg";

    const filename =
        `${folder}/${Date.now()}-${Math.random()
            .toString(36)
            .slice(2)}${extension}`;


    const result =
        await supabase.storage
            .from(storage_bucket)
            .upload(
                filename,
                file.buffer,
                {
                    contentType:
                        file.mimetype,

                    upsert: false
                }
            );


    if (result.error) {
        throw result.error;
    }


    const public_url =
        supabase.storage
            .from(storage_bucket)
            .getPublicUrl(filename)
            .data
            .publicUrl;


    return public_url;
}


/* =========================================================
   current user
   ========================================================= */

app.use(async (req, res, next) => {

    req.user = null;

    res.locals.user = null;

    if (!req.session.user_id) {
        return next();
    }

    try {

        /*
         * IMPORTANT:
         *
         * this query intentionally supports the exact
         * users table currently in your database.
         */

        const result = await pool.query(
            `
            select
                id,
                username,
                email,
                display_name,
                bio,
                profile_picture,
                profile_image_url,
                is_admin,
                created_at
            from users
            where id = $1
            limit 1
            `,
            [req.session.user_id]
        );


        if (!result.rows.length) {

            req.session.destroy(() => {});

            return next();
        }


        req.user = result.rows[0];

        res.locals.user = result.rows[0];

    } catch (error) {

        console.error(
            "current user error:"
        );

        console.error(error);

        /*
         * don't destroy the session just because
         * a temporary database error occurred.
         */

    }

    next();
});


/* =========================================================
   global template helpers
   ========================================================= */

app.use((req, res, next) => {

    res.locals.formatDate = formatDate;

    res.locals.currentPath =
        req.path;

    next();
});


/* =========================================================
   database initialization
   ========================================================= */

async function initializeDatabase() {

    /*
     * users already exists in your database.
     *
     * These alter statements only add missing compatibility
     * columns and do not delete your existing data.
     */

    await pool.query(`
        alter table users
        add column if not exists email varchar(255)
    `);

    await pool.query(`
        alter table users
        add column if not exists password varchar(255)
    `);

    await pool.query(`
        alter table users
        add column if not exists password_hash varchar(255)
    `);

    await pool.query(`
        alter table users
        add column if not exists bio text
    `);

    await pool.query(`
        alter table users
        add column if not exists display_name varchar(100)
    `);

    await pool.query(`
        alter table users
        add column if not exists profile_picture text
    `);

    await pool.query(`
        alter table users
        add column if not exists profile_image_url text
    `);

    await pool.query(`
        alter table users
        add column if not exists is_admin boolean default false
    `);

    await pool.query(`
        alter table users
        add column if not exists created_at timestamptz default now()
    `);


    /* =====================================================
       communities
       ===================================================== */

    await pool.query(`
        create table if not exists communities (
            id serial primary key,

            name varchar(50) unique not null,

            description text,

            creator_id integer
                references users(id)
                on delete set null,

            created_at timestamptz default now()
        )
    `);


    /* =====================================================
       community members
       ===================================================== */

    await pool.query(`
        create table if not exists community_members (
            id serial primary key,

            community_id integer
                references communities(id)
                on delete cascade,

            user_id integer
                references users(id)
                on delete cascade,

            created_at timestamptz default now(),

            unique(community_id, user_id)
        )
    `);


    /* =====================================================
       posts
       ===================================================== */

    await pool.query(`
        create table if not exists posts (
            id serial primary key,

            user_id integer
                references users(id)
                on delete cascade,

            community_id integer
                references communities(id)
                on delete set null,

            content text not null,

            attachment_url text,

            attachment_name text,

            created_at timestamptz default now()
        )
    `);


    /* =====================================================
       likes
       ===================================================== */

    await pool.query(`
        create table if not exists likes (
            id serial primary key,

            user_id integer
                references users(id)
                on delete cascade,

            post_id integer
                references posts(id)
                on delete cascade,

            created_at timestamptz default now(),

            unique(user_id, post_id)
        )
    `);


    /* =====================================================
       comments
       ===================================================== */

    await pool.query(`
        create table if not exists comments (
            id serial primary key,

            user_id integer
                references users(id)
                on delete cascade,

            post_id integer
                references posts(id)
                on delete cascade,

            content text not null,

            created_at timestamptz default now()
        )
    `);


    /* =====================================================
       follows
       ===================================================== */

    await pool.query(`
        create table if not exists follows (
            id serial primary key,

            follower_id integer
                references users(id)
                on delete cascade,

            following_id integer
                references users(id)
                on delete cascade,

            created_at timestamptz default now(),

            unique(follower_id, following_id)
        )
    `);


    /*
     * synchronize the old password column with the new
     * password_hash column where possible.
     */

    await pool.query(`
        update users
        set password_hash = password
        where
            (
                password_hash is null
                or password_hash = ''
            )
            and password is not null
            and password <> ''
    `);


    /*
     * synchronize profile image columns.
     */

    await pool.query(`
        update users
        set profile_image_url = profile_picture
        where
            (
                profile_image_url is null
                or profile_image_url = ''
            )
            and profile_picture is not null
            and profile_picture <> ''
    `);


    console.log(
        "database initialized successfully"
    );
}


/* =========================================================
   home
   ========================================================= */

app.get("/", (req, res) => {

    if (req.user) {
        return res.redirect("/feed");
    }

    res.redirect("/login");
});


/* =========================================================
   register
   ========================================================= */

app.get("/register", (req, res) => {

    if (req.user) {
        return res.redirect("/feed");
    }

    res.render("register", {
        error: null
    });
});


app.post("/register", async (req, res) => {

    try {

        const username =
            String(
                req.body.username || ""
            )
                .trim()
                .toLowerCase();

        const email =
            String(
                req.body.email || ""
            )
                .trim()
                .toLowerCase();

        const password =
            String(
                req.body.password || ""
            );


        if (
            !username ||
            !email ||
            !password
        ) {

            return res.render(
                "register",
                {
                    error:
                        "all fields are required"
                }
            );
        }


        if (
            !/^[a-z0-9_]{3,32}$/
                .test(username)
        ) {

            return res.render(
                "register",
                {
                    error:
                        "username must be 3-32 characters and use only letters, numbers, and underscores"
                }
            );
        }


        if (password.length < 6) {

            return res.render(
                "register",
                {
                    error:
                        "password must be at least 6 characters"
                }
            );
        }


        const existing =
            await pool.query(
                `
                select id
                from users
                where
                    lower(username) = lower($1)
                    or lower(email) = lower($2)
                limit 1
                `,
                [
                    username,
                    email
                ]
            );


        if (existing.rows.length) {

            return res.render(
                "register",
                {
                    error:
                        "that username or email is already in use"
                }
            );
        }


        const password_hash =
            await bcrypt.hash(
                password,
                12
            );


        const result =
            await pool.query(
                `
                insert into users (
                    username,
                    email,
                    password,
                    password_hash,
                    display_name,
                    bio,
                    is_admin,
                    created_at
                )
                values (
                    $1,
                    $2,
                    $3,
                    $3,
                    $4,
                    '',
                    false,
                    now()
                )
                returning id
                `,
                [
                    username,
                    email,
                    password_hash,
                    username
                ]
            );


        req.session.user_id =
            result.rows[0].id;


        req.session.save((error) => {

            if (error) {

                console.error(
                    "register session error:"
                );

                console.error(error);

                return res.status(500).send(
                    "internal server error"
                );
            }

            res.redirect("/feed");
        });


    } catch (error) {

        console.error(
            "register error:"
        );

        console.error(error);

        res.status(500).send(
            "internal server error"
        );
    }
});


/* =========================================================
   login
   ========================================================= */

app.get("/login", (req, res) => {

    if (req.user) {
        return res.redirect("/feed");
    }

    res.render("login", {
        error: null
    });
});


app.post("/login", async (req, res) => {

    try {

        const username =
            String(
                req.body.username || ""
            )
                .trim()
                .toLowerCase();

        const password =
            String(
                req.body.password || ""
            );


        console.log(
            "login attempt for:",
            username
        );


        if (
            !username ||
            !password
        ) {

            return res.render(
                "login",
                {
                    error:
                        "username and password are required"
                }
            );
        }


        /*
         * IMPORTANT:
         *
         * We query BOTH password columns because your
         * existing database contains both.
         */

        const result =
            await pool.query(
                `
                select
                    id,
                    username,
                    email,
                    password,
                    password_hash,
                    display_name,
                    bio,
                    profile_picture,
                    profile_image_url,
                    is_admin,
                    created_at
                from users
                where lower(username) = lower($1)
                limit 1
                `,
                [username]
            );


        if (!result.rows.length) {

            console.log(
                "login failed: user not found"
            );

            return res.render(
                "login",
                {
                    error:
                        "invalid username or password"
                }
            );
        }


        const user =
            result.rows[0];


        /*
         * prefer password_hash, but support the old
         * password column as a fallback.
         */

        const stored_hash =
            user.password_hash ||
            user.password;


        if (!stored_hash) {

            console.log(
                "login failed: account has no password hash"
            );

            return res.render(
                "login",
                {
                    error:
                        "this account needs to be reset"
                }
            );
        }


        const valid =
            await bcrypt.compare(
                password,
                stored_hash
            );


        if (!valid) {

            console.log(
                "login failed: incorrect password"
            );

            return res.render(
                "login",
                {
                    error:
                        "invalid username or password"
                }
            );
        }


        /*
         * If the account was using the old password column,
         * automatically migrate it to password_hash.
         */

        if (
            !user.password_hash &&
            user.password
        ) {

            await pool.query(
                `
                update users
                set password_hash = password
                where id = $1
                `,
                [user.id]
            );
        }


        req.session.user_id =
            user.id;


        req.session.save((error) => {

            if (error) {

                console.error(
                    "session save error:"
                );

                console.error(error);

                return res.status(500).send(
                    "internal server error"
                );
            }


            console.log(
                "login successful for:",
                user.username
            );


            res.redirect("/feed");
        });


    } catch (error) {

        console.error(
            "login error:"
        );

        console.error(error);

        res.status(500).send(
            "internal server error"
        );
    }
});


/* =========================================================
   logout
   ========================================================= */

app.post("/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {
            console.error(
                "logout error:",
                error
            );
        }

        res.clearCookie("connect.sid");

        res.redirect("/login");
    });
});


/* =========================================================
   feed
   ========================================================= */

app.get(
    "/feed",
    requireLogin,
    async (req, res) => {

        try {

            const posts =
                await pool.query(
                    `
                    select
                        p.*,

                        u.username,
                        u.display_name,
                        u.profile_picture,
                        u.profile_image_url,

                        c.name as community_name,

                        (
                            select count(*)
                            from likes l
                            where l.post_id = p.id
                        ) as likes,

                        (
                            select count(*)
                            from comments cm
                            where cm.post_id = p.id
                        ) as comments,

                        exists (
                            select 1
                            from likes l2
                            where
                                l2.post_id = p.id
                                and l2.user_id = $1
                        ) as liked

                    from posts p

                    join users u
                        on u.id = p.user_id

                    left join communities c
                        on c.id = p.community_id

                    order by p.created_at desc

                    limit 100
                    `,
                    [req.user.id]
                );


            const community_result =
                await pool.query(
                    `
                    select
                        c.*,

                        count(p.id)::integer
                            as post_count

                    from communities c

                    left join posts p
                        on p.community_id = c.id

                    group by c.id

                    order by c.name asc
                    `
                );


            for (
                const post
                of posts.rows
            ) {

                const comments =
                    await pool.query(
                        `
                        select
                            cm.id,
                            cm.content,
                            cm.created_at,
                            u.username,
                            u.display_name

                        from comments cm

                        join users u
                            on u.id = cm.user_id

                        where cm.post_id = $1

                        order by
                            cm.created_at desc

                        limit 3
                        `,
                        [post.id]
                    );


                post.comment_list =
                    comments.rows;
            }


            res.render(
                "feed",
                {
                    user: req.user,

                    posts:
                        posts.rows,

                    communities:
                        community_result.rows
                }
            );


        } catch (error) {

            console.error(
                "feed error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   create post
   ========================================================= */

app.post(
    "/posts",
    requireLogin,
    upload.single("attachment"),
    async (req, res) => {

        try {

            const content =
                String(
                    req.body.content || ""
                ).trim();


            const community_id =
                req.body.community_id
                    ? Number(
                        req.body.community_id
                    )
                    : null;


            if (!content) {
                return res.redirect(
                    "/feed"
                );
            }


            if (content.length > 500) {

                return res.status(400).send(
                    "post is too long"
                );
            }


            let attachment_url =
                null;

            let attachment_name =
                null;


            if (req.file) {

                attachment_url =
                    await uploadToSupabase(
                        req.file,
                        `posts/${req.user.id}`
                    );

                attachment_name =
                    req.file.originalname;
            }


            await pool.query(
                `
                insert into posts (
                    user_id,
                    community_id,
                    content,
                    attachment_url,
                    attachment_name
                )
                values (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5
                )
                `,
                [
                    req.user.id,
                    community_id,
                    content,
                    attachment_url,
                    attachment_name
                ]
            );


            res.redirect("/feed");


        } catch (error) {

            console.error(
                "create post error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   like
   ========================================================= */

app.post(
    "/posts/:id/like",
    requireLogin,
    async (req, res) => {

        try {

            const post_id =
                Number(req.params.id);


            const existing =
                await pool.query(
                    `
                    select id
                    from likes
                    where
                        user_id = $1
                        and post_id = $2
                    limit 1
                    `,
                    [
                        req.user.id,
                        post_id
                    ]
                );


            if (existing.rows.length) {

                await pool.query(
                    `
                    delete from likes
                    where
                        user_id = $1
                        and post_id = $2
                    `,
                    [
                        req.user.id,
                        post_id
                    ]
                );

            } else {

                await pool.query(
                    `
                    insert into likes (
                        user_id,
                        post_id
                    )
                    values ($1, $2)
                    on conflict do nothing
                    `,
                    [
                        req.user.id,
                        post_id
                    ]
                );
            }


            res.redirect(
                req.get("referer") ||
                "/feed"
            );


        } catch (error) {

            console.error(
                "like error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   comments page
   ========================================================= */

app.get(
    "/posts/:id/comments",
    requireLogin,
    async (req, res) => {

        try {

            const post =
                await pool.query(
                    `
                    select
                        p.*,

                        u.username,
                        u.display_name,

                        c.name as community_name

                    from posts p

                    join users u
                        on u.id = p.user_id

                    left join communities c
                        on c.id = p.community_id

                    where p.id = $1

                    limit 1
                    `,
                    [req.params.id]
                );


            if (!post.rows.length) {

                return res.status(404).send(
                    "post not found"
                );
            }


            const comments =
                await pool.query(
                    `
                    select
                        cm.*,

                        u.username,
                        u.display_name

                    from comments cm

                    join users u
                        on u.id = cm.user_id

                    where cm.post_id = $1

                    order by cm.created_at asc
                    `,
                    [req.params.id]
                );


            res.render(
                "comments",
                {
                    user: req.user,

                    post:
                        post.rows[0],

                    comments:
                        comments.rows
                }
            );


        } catch (error) {

            console.error(
                "comments page error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   create comment
   ========================================================= */

app.post(
    "/posts/:id/comments",
    requireLogin,
    async (req, res) => {

        try {

            const content =
                String(
                    req.body.content || ""
                ).trim();


            if (!content) {

                return res.redirect(
                    `/posts/${req.params.id}/comments`
                );
            }


            if (content.length > 300) {

                return res.status(400).send(
                    "comment is too long"
                );
            }


            await pool.query(
                `
                insert into comments (
                    user_id,
                    post_id,
                    content
                )
                values (
                    $1,
                    $2,
                    $3
                )
                `,
                [
                    req.user.id,
                    req.params.id,
                    content
                ]
            );


            res.redirect(
                `/posts/${req.params.id}/comments`
            );


        } catch (error) {

            console.error(
                "comment error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   delete post
   ========================================================= */

app.post(
    "/posts/:id/delete",
    requireLogin,
    async (req, res) => {

        try {

            await pool.query(
                `
                delete from posts

                where id = $1

                and (
                    user_id = $2

                    or exists (
                        select 1
                        from users
                        where
                            id = $2
                            and is_admin = true
                    )
                )
                `,
                [
                    req.params.id,
                    req.user.id
                ]
            );


            res.redirect(
                req.get("referer") ||
                "/feed"
            );


        } catch (error) {

            console.error(
                "delete post error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   profile
   ========================================================= */

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


            const profile_result =
                await pool.query(
                    `
                    select
                        id,
                        username,
                        email,
                        display_name,
                        bio,
                        profile_picture,
                        profile_image_url,
                        is_admin,
                        created_at

                    from users

                    where
                        lower(username) = lower($1)

                    limit 1
                    `,
                    [username]
                );


            if (
                !profile_result.rows.length
            ) {

                return res.status(404).render(
                    "404"
                );
            }


            const profile =
                profile_result.rows[0];


            const posts_result =
                await pool.query(
                    `
                    select
                        p.*,

                        c.name as community_name,

                        (
                            select count(*)
                            from comments cm
                            where cm.post_id = p.id
                        ) as comments,

                        (
                            select count(*)
                            from likes l
                            where l.post_id = p.id
                        ) as likes

                    from posts p

                    left join communities c
                        on c.id = p.community_id

                    where p.user_id = $1

                    order by p.created_at desc

                    limit 100
                    `,
                    [profile.id]
                );


            res.render(
                "profile",
                {
                    user: req.user,

                    profile: profile,

                    posts:
                        posts_result.rows
                }
            );


        } catch (error) {

            console.error(
                "profile page error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   profile settings
   ========================================================= */

app.get(
    "/settings/profile",
    requireLogin,
    (req, res) => {

        res.render(
            "profile-settings",
            {
                user: req.user,

                error: null,

                success: null
            }
        );
    }
);


app.post(
    "/settings/profile",
    requireLogin,
    upload.single("profile_picture"),
    async (req, res) => {

        try {

            const display_name =
                String(
                    req.body.display_name || ""
                ).trim();


            const bio =
                String(
                    req.body.bio || ""
                ).trim();


            let profile_picture =
                req.user.profile_picture ||
                req.user.profile_image_url ||
                null;


            if (req.file) {

                profile_picture =
                    await uploadToSupabase(
                        req.file,
                        `profiles/${req.user.id}`
                    );
            }


            await pool.query(
                `
                update users

                set
                    display_name = $1,
                    bio = $2,
                    profile_picture = $3,
                    profile_image_url = $3

                where id = $4
                `,
                [
                    display_name ||
                        req.user.username,

                    bio,

                    profile_picture,

                    req.user.id
                ]
            );


            res.redirect(
                `/u/${req.user.username}`
            );


        } catch (error) {

            console.error(
                "profile settings error:"
            );

            console.error(error);


            res.render(
                "profile-settings",
                {
                    user: req.user,

                    error:
                        "could not update your profile",

                    success: null
                }
            );
        }
    }
);


/* =========================================================
   communities
   ========================================================= */

app.get(
    "/communities",
    requireLogin,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    select
                        c.*,

                        u.username
                            as creator_username,

                        count(p.id)::integer
                            as post_count

                    from communities c

                    left join users u
                        on u.id = c.creator_id

                    left join posts p
                        on p.community_id = c.id

                    group by
                        c.id,
                        u.username

                    order by c.name asc
                    `
                );


            res.render(
                "communities",
                {
                    user: req.user,

                    communities:
                        result.rows
                }
            );


        } catch (error) {

            console.error(
                "communities error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   create community
   ========================================================= */

app.post(
    "/communities",
    requireLogin,
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
                    req.body.description || ""
                ).trim();


            if (
                !/^[a-z0-9_]{2,50}$/
                    .test(name)
            ) {

                return res.status(400).send(
                    "community name must use only letters, numbers, and underscores"
                );
            }


            await pool.query(
                `
                insert into communities (
                    name,
                    description,
                    creator_id
                )
                values (
                    $1,
                    $2,
                    $3
                )
                `,
                [
                    name,
                    description,
                    req.user.id
                ]
            );


            res.redirect(
                "/communities"
            );


        } catch (error) {

            console.error(
                "create community error:"
            );

            console.error(error);


            if (
                error.code === "23505"
            ) {

                return res.status(400).send(
                    "that community already exists"
                );
            }


            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   community page
   ========================================================= */

app.get(
    "/c/:name",
    requireLogin,
    async (req, res) => {

        try {

            const name =
                String(
                    req.params.name
                )
                    .trim()
                    .toLowerCase();


            const community_result =
                await pool.query(
                    `
                    select
                        c.*,

                        u.username
                            as creator_username

                    from communities c

                    left join users u
                        on u.id = c.creator_id

                    where
                        lower(c.name) = lower($1)

                    limit 1
                    `,
                    [name]
                );


            if (
                !community_result.rows.length
            ) {

                return res.status(404).render(
                    "404"
                );
            }


            const community =
                community_result.rows[0];


            const posts_result =
                await pool.query(
                    `
                    select
                        p.*,

                        u.username,
                        u.display_name,
                        u.profile_picture,
                        u.profile_image_url,

                        (
                            select count(*)
                            from likes l
                            where l.post_id = p.id
                        ) as likes,

                        (
                            select count(*)
                            from comments cm
                            where cm.post_id = p.id
                        ) as comments,

                        exists (
                            select 1
                            from likes l2
                            where
                                l2.post_id = p.id
                                and l2.user_id = $2
                        ) as liked

                    from posts p

                    join users u
                        on u.id = p.user_id

                    where
                        p.community_id = $1

                    order by
                        p.created_at desc

                    limit 100
                    `,
                    [
                        community.id,
                        req.user.id
                    ]
                );


            res.render(
                "community",
                {
                    user: req.user,

                    community:
                        community,

                    posts:
                        posts_result.rows
                }
            );


        } catch (error) {

            console.error(
                "community page error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   search
   ========================================================= */

app.get(
    "/search",
    requireLogin,
    async (req, res) => {

        try {

            const query =
                String(
                    req.query.q || ""
                ).trim();


            let users = [];

            let communities = [];

            let posts = [];


            if (query) {

                const search =
                    `%${query}%`;


                const users_result =
                    await pool.query(
                        `
                        select
                            id,
                            username,
                            display_name,
                            profile_picture,
                            profile_image_url

                        from users

                        where
                            username ilike $1
                            or display_name ilike $1

                        order by username

                        limit 25
                        `,
                        [search]
                    );


                const communities_result =
                    await pool.query(
                        `
                        select
                            c.*,

                            count(p.id)::integer
                                as post_count

                        from communities c

                        left join posts p
                            on p.community_id = c.id

                        where
                            c.name ilike $1
                            or c.description ilike $1

                        group by c.id

                        order by c.name

                        limit 25
                        `,
                        [search]
                    );


                const posts_result =
                    await pool.query(
                        `
                        select
                            p.id,
                            p.content,
                            p.created_at,

                            u.username,

                            c.name
                                as community_name

                        from posts p

                        join users u
                            on u.id = p.user_id

                        left join communities c
                            on c.id = p.community_id

                        where
                            p.content ilike $1

                        order by
                            p.created_at desc

                        limit 50
                        `,
                        [search]
                    );


                users =
                    users_result.rows;

                communities =
                    communities_result.rows;

                posts =
                    posts_result.rows;
            }


            res.render(
                "search",
                {
                    user: req.user,

                    query: query,

                    users: users,

                    communities:
                        communities,

                    posts: posts
                }
            );


        } catch (error) {

            console.error(
                "search error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   admin
   ========================================================= */

app.get(
    "/admin",
    requireAdmin,
    async (req, res) => {

        try {

            const users =
                await pool.query(
                    `
                    select
                        id,
                        username,
                        email,
                        is_admin,
                        created_at

                    from users

                    order by
                        created_at desc

                    limit 100
                    `
                );


            const posts =
                await pool.query(
                    `
                    select
                        p.id,
                        p.content,
                        p.created_at,

                        u.username

                    from posts p

                    join users u
                        on u.id = p.user_id

                    order by
                        p.created_at desc

                    limit 100
                    `
                );


            const communities =
                await pool.query(
                    `
                    select
                        c.id,
                        c.name,
                        c.description,
                        c.created_at,

                        u.username
                            as creator_username

                    from communities c

                    left join users u
                        on u.id = c.creator_id

                    order by
                        c.created_at desc

                    limit 100
                    `
                );


            res.render(
                "admin",
                {
                    user: req.user,

                    users:
                        users.rows,

                    posts:
                        posts.rows,

                    communities:
                        communities.rows
                }
            );


        } catch (error) {

            console.error(
                "admin error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   admin delete post
   ========================================================= */

app.post(
    "/admin/posts/:id/delete",
    requireAdmin,
    async (req, res) => {

        try {

            await pool.query(
                `
                delete from posts
                where id = $1
                `,
                [req.params.id]
            );


            res.redirect(
                "/admin"
            );


        } catch (error) {

            console.error(
                "admin delete post error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   admin delete user
   ========================================================= */

app.post(
    "/admin/users/:id/delete",
    requireAdmin,
    async (req, res) => {

        try {

            const target_id =
                Number(
                    req.params.id
                );


            if (
                target_id ===
                Number(req.user.id)
            ) {

                return res.status(400).send(
                    "you cannot delete yourself"
                );
            }


            await pool.query(
                `
                delete from users
                where id = $1
                `,
                [target_id]
            );


            res.redirect(
                "/admin"
            );


        } catch (error) {

            console.error(
                "admin delete user error:"
            );

            console.error(error);

            res.status(500).send(
                "internal server error"
            );
        }
    }
);


/* =========================================================
   health
   ========================================================= */

app.get(
    "/health",
    async (req, res) => {

        try {

            await pool.query(
                "select 1"
            );


            res.json({
                status: "ok"
            });


        } catch (error) {

            console.error(
                "health check error:",
                error
            );


            res.status(500).json({
                status: "error"
            });
        }
    }
);


/* =========================================================
   404
   ========================================================= */

app.use(
    (req, res) => {

        res.status(404);

        res.render(
            "404"
        );
    }
);


/* =========================================================
   upload / application error handler
   ========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "server error:"
        );

        console.error(error);


        if (
            error instanceof
            multer.MulterError
        ) {

            if (
                error.code ===
                "LIMIT_FILE_SIZE"
            ) {

                return res.status(400).send(
                    "file is too large. maximum size is 15mb"
                );
            }
        }


        if (
            error.message ===
            "only image files are allowed"
        ) {

            return res.status(400).send(
                "only png, jpeg, gif, and webp images are allowed"
            );
        }


        res.status(500).send(
            "internal server error"
        );
    }
);


/* =========================================================
   start
   ========================================================= */

async function startServer() {

    try {

        await initializeDatabase();


        app.listen(
            port,
            "0.0.0.0",
            () => {

                console.log(
                    `helloworld running on port ${port}`
                );

                console.log(
                    `port: ${port}`
                );
            }
        );


    } catch (error) {

        console.error(
            "failed to initialize database:"
        );

        console.error(error);

        process.exit(1);
    }
}


startServer();