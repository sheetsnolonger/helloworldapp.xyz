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

const PORT = Number(process.env.PORT) || 3000;


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

const SUPABASE_URL =
    String(process.env.SUPABASE_URL || "").trim();

const SUPABASE_SERVICE_ROLE_KEY =
    String(
        process.env.SUPABASE_SERVICE_ROLE_KEY || ""
    ).trim();

const STORAGE_BUCKET =
    String(
        process.env.SUPABASE_STORAGE_BUCKET || "uploads"
    ).trim();

if (
    SUPABASE_URL &&
    SUPABASE_SERVICE_ROLE_KEY
) {
    supabase = createClient(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY,
        {
            auth: {
                autoRefreshToken: false,
                persistSession: false
            }
        }
    );

    console.log("supabase storage enabled");
} else {
    console.log(
        "supabase storage disabled - using local uploads"
    );
}


/* =========================================================
   express
   ========================================================= */

app.set(
    "view engine",
    "ejs"
);

app.set(
    "views",
    path.join(__dirname, "views")
);

app.set(
    "trust proxy",
    1
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "2mb"
    })
);

app.use(
    express.json({
        limit: "2mb"
    })
);

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);


/* =========================================================
   uploads
   ========================================================= */

const uploadDirectory =
    path.join(
        __dirname,
        "uploads"
    );

if (
    !fs.existsSync(uploadDirectory)
) {
    fs.mkdirSync(
        uploadDirectory,
        {
            recursive: true
        }
    );
}

app.use(
    "/uploads",
    express.static(uploadDirectory)
);


const allowedMimeTypes = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp"
];


const upload = multer({
    storage: multer.memoryStorage(),

    limits: {
        fileSize:
            15 * 1024 * 1024,

        files: 1
    },

    fileFilter: (req, file, callback) => {

        if (
            !allowedMimeTypes.includes(
                file.mimetype
            )
        ) {
            return callback(
                new Error(
                    "only image files are allowed"
                )
            );
        }

        callback(null, true);
    }
});


/* =========================================================
   session
   ========================================================= */

/*
    IMPORTANT:

    there should only be ONE session middleware.

    the old server had two separate app.use(session(...))
    calls, which could overwrite session behavior.
*/

const sessionSecret =
    process.env.SESSION_SECRET ||
    "helloworld-development-secret-change-me";

app.use(
    session({
        store: new pgSession({
            pool: pool,
            tableName: "user_sessions",
            createTableIfMissing: true
        }),

        secret: sessionSecret,

        resave: false,

        saveUninitialized: false,

        rolling: true,

        proxy:
            process.env.NODE_ENV ===
            "production",

        cookie: {
            httpOnly: true,

            secure:
                process.env.NODE_ENV ===
                "production",

            sameSite: "lax",

            maxAge:
                1000 *
                60 *
                60 *
                24 *
                30
        }
    })
);


/* =========================================================
   helpers
   ========================================================= */

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


function requireLogin(req, res, next) {

    if (!req.session.user_id) {
        return res.redirect("/login");
    }

    next();
}


function requireAdmin(req, res, next) {

    if (!req.session.user_id) {
        return res.redirect("/login");
    }

    if (
        !req.user ||
        !req.user.is_admin
    ) {
        return res.status(403).send(
            "you do not have permission to access this page"
        );
    }

    next();
}


function getFileExtension(file) {

    const extension =
        path.extname(
            file.originalname || ""
        ).toLowerCase();

    const allowedExtensions = [
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp"
    ];

    if (
        allowedExtensions.includes(
            extension
        )
    ) {
        return extension;
    }

    switch (file.mimetype) {

        case "image/png":
            return ".png";

        case "image/gif":
            return ".gif";

        case "image/webp":
            return ".webp";

        default:
            return ".jpg";
    }
}


/* =========================================================
   local upload
   ========================================================= */

async function uploadToLocal(
    file,
    folder
) {

    if (!file) {
        return null;
    }

    const safeFolder =
        String(folder || "uploads")
            .replace(/[^a-zA-Z0-9/_-]/g, "");

    const destination =
        path.join(
            uploadDirectory,
            safeFolder
        );

    await fs.promises.mkdir(
        destination,
        {
            recursive: true
        }
    );

    const extension =
        getFileExtension(file);

    const filename =
        `${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}${extension}`;

    const filePath =
        path.join(
            destination,
            filename
        );

    await fs.promises.writeFile(
        filePath,
        file.buffer
    );

    return `/uploads/${safeFolder}/${filename}`;
}


/* =========================================================
   supabase upload
   ========================================================= */

async function uploadToSupabase(
    file,
    folder
) {

    if (!file) {
        return null;
    }

    if (!supabase) {
        return null;
    }

    const extension =
        getFileExtension(file);

    const filename =
        `${folder}/${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}${extension}`;

    const result =
        await supabase.storage
            .from(STORAGE_BUCKET)
            .upload(
                filename,
                file.buffer,
                {
                    contentType:
                        file.mimetype,

                    upsert: false,

                    cacheControl:
                        "3600"
                }
            );

    if (result.error) {
        throw result.error;
    }

    const publicResult =
        supabase.storage
            .from(STORAGE_BUCKET)
            .getPublicUrl(
                filename
            );

    if (
        publicResult.error
    ) {
        throw publicResult.error;
    }

    return publicResult
        .data
        .publicUrl;
}


/* =========================================================
   universal upload
   ========================================================= */

/*
    if supabase exists:
        upload to supabase

    if supabase doesn't exist:
        upload locally

    this means the application no longer crashes with:

        "supabase storage is not configured"
*/

async function saveUploadedFile(
    file,
    folder
) {

    if (!file) {
        return null;
    }

    if (supabase) {

        try {

            const url =
                await uploadToSupabase(
                    file,
                    folder
                );

            if (url) {
                return url;
            }

        } catch (error) {

            console.error(
                "supabase upload failed:"
            );

            console.error(error);

            console.log(
                "falling back to local upload"
            );
        }
    }

    return uploadToLocal(
        file,
        folder
    );
}


/* =========================================================
   globals / current user
   ========================================================= */

app.use(
    async (req, res, next) => {

        req.user = null;

        res.locals.user = null;

        res.locals.formatDate =
            formatDate;

        if (!req.session.user_id) {
            return next();
        }

        try {

            const result =
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
                    where id = $1
                    limit 1
                    `,
                    [
                        req.session.user_id
                    ]
                );

            if (
                result.rows.length
            ) {

                req.user =
                    result.rows[0];

                /*
                    Keep both names available.

                    Some older templates use
                    profile_picture and others use
                    profile_image_url.
                */

                if (
                    !req.user.profile_picture &&
                    req.user.profile_image_url
                ) {
                    req.user.profile_picture =
                        req.user.profile_image_url;
                }

                if (
                    !req.user.profile_image_url &&
                    req.user.profile_picture
                ) {
                    req.user.profile_image_url =
                        req.user.profile_picture;
                }

                res.locals.user =
                    req.user;

            } else {

                req.session.destroy(
                    () => {}
                );
            }

        } catch (error) {

            console.error(
                "user middleware error:"
            );

            console.error(error);
        }

        next();
    }
);


/* =========================================================
   database initialization
   ========================================================= */

async function initializeDatabase() {

    /*
        users may already exist in your database.
        this only creates it if it doesn't.
    */

    await pool.query(`
        create table if not exists users (
            id serial primary key,
            username varchar(32) unique not null,
            email varchar(255) unique not null,
            password_hash text not null,
            display_name varchar(100),
            bio text,
            profile_picture text,
            profile_image_url text,
            is_admin boolean default false,
            created_at timestamptz default now()
        )
    `);

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
        Make sure older databases have both profile columns.
    */

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
        add column if not exists display_name varchar(100)
    `);

    await pool.query(`
        alter table users
        add column if not exists bio text
    `);

    await pool.query(`
        alter table users
        add column if not exists is_admin boolean default false
    `);

    /*
        Keep the two profile image fields synchronized
        for old accounts.
    */

    await pool.query(`
        update users
        set profile_image_url = profile_picture
        where profile_image_url is null
        and profile_picture is not null
    `);

    await pool.query(`
        update users
        set profile_picture = profile_image_url
        where profile_picture is null
        and profile_image_url is not null
    `);

    console.log(
        "database initialized"
    );
}


/* =========================================================
   home
   ========================================================= */

app.get(
    "/",
    (req, res) => {

        if (req.user) {
            return res.redirect(
                "/feed"
            );
        }

        res.redirect(
            "/login"
        );
    }
);


/* =========================================================
   register
   ========================================================= */

app.get(
    "/register",
    (req, res) => {

        if (req.user) {
            return res.redirect(
                "/feed"
            );
        }

        res.render(
            "register",
            {
                error: null
            }
        );
    }
);


app.post(
    "/register",
    async (req, res) => {

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
                !/^[a-z0-9_]{3,32}$/.test(
                    username
                )
            ) {
                return res.render(
                    "register",
                    {
                        error:
                            "username must be 3-32 characters and use only letters, numbers, and underscores"
                    }
                );
            }

            if (
                password.length < 6
            ) {
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
                    where username = $1
                    or email = $2
                    limit 1
                    `,
                    [
                        username,
                        email
                    ]
                );

            if (
                existing.rows.length
            ) {
                return res.render(
                    "register",
                    {
                        error:
                            "that username or email is already in use"
                    }
                );
            }

            const passwordHash =
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
                        password_hash,
                        display_name
                    )
                    values (
                        $1,
                        $2,
                        $3,
                        $4
                    )
                    returning id
                    `,
                    [
                        username,
                        email,
                        passwordHash,
                        username
                    ]
                );

            req.session.user_id =
                result.rows[0].id;

            req.session.save(
                (error) => {

                    if (error) {

                        console.error(
                            "register session error:"
                        );

                        console.error(
                            error
                        );

                        return res
                            .status(500)
                            .render(
                                "register",
                                {
                                    error:
                                        "account created, but the login session could not be created"
                                }
                            );
                    }

                    res.redirect(
                        "/feed"
                    );
                }
            );

        } catch (error) {

            console.error(
                "register error:"
            );

            console.error(error);

            res.status(500).render(
                "register",
                {
                    error:
                        "internal server error"
                }
            );
        }
    }
);


/* =========================================================
   login
   ========================================================= */

app.get(
    "/login",
    (req, res) => {

        if (req.user) {
            return res.redirect(
                "/feed"
            );
        }

        res.render(
            "login",
            {
                error: null
            }
        );
    }
);


app.post(
    "/login",
    async (req, res) => {

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

            const result =
                await pool.query(
                    `
                    select
                        id,
                        username,
                        email,
                        password_hash,
                        display_name,
                        bio,
                        profile_picture,
                        profile_image_url,
                        is_admin,
                        created_at
                    from users
                    where username = $1
                    limit 1
                    `,
                    [
                        username
                    ]
                );

            if (
                !result.rows.length
            ) {
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

            const valid =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!valid) {
                return res.render(
                    "login",
                    {
                        error:
                            "invalid username or password"
                    }
                );
            }

            req.session.regenerate(
                (error) => {

                    if (error) {

                        console.error(
                            "session regenerate error:"
                        );

                        console.error(error);

                        return res
                            .status(500)
                            .render(
                                "login",
                                {
                                    error:
                                        "could not create your login session"
                                }
                            );
                    }

                    req.session.user_id =
                        user.id;

                    req.session.save(
                        (saveError) => {

                            if (
                                saveError
                            ) {

                                console.error(
                                    "session save error:"
                                );

                                console.error(
                                    saveError
                                );

                                return res
                                    .status(500)
                                    .render(
                                        "login",
                                        {
                                            error:
                                                "could not save your login session"
                                        }
                                    );
                            }

                            res.redirect(
                                "/feed"
                            );
                        }
                    );
                }
            );

        } catch (error) {

            console.error(
                "login error:"
            );

            console.error(error);

            res.status(500).render(
                "login",
                {
                    error:
                        "internal server error"
                }
            );
        }
    }
);


/* =========================================================
   logout
   ========================================================= */

app.post(
    "/logout",
    (req, res) => {

        req.session.destroy(
            (error) => {

                if (error) {
                    console.error(
                        "logout error:"
                    );

                    console.error(error);
                }

                res.clearCookie(
                    "connect.sid"
                );

                res.redirect(
                    "/login"
                );
            }
        );
    }
);


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
                            where l2.post_id = p.id
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
                    [
                        req.user.id
                    ]
                );

            const communities =
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
                const post of posts.rows
            ) {

                const comments =
                    await pool.query(
                        `
                        select
                            cm.id,
                            cm.content,
                            cm.created_at,
                            u.username,
                            u.display_name,
                            u.profile_picture,
                            u.profile_image_url
                        from comments cm
                        join users u
                            on u.id = cm.user_id
                        where cm.post_id = $1
                        order by cm.created_at desc
                        limit 3
                        `,
                        [
                            post.id
                        ]
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
                        communities.rows
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

            const communityId =
                req.body.community_id
                    ? Number(
                        req.body.community_id
                    )
                    : null;

            if (
                !content &&
                !req.file
            ) {
                return res.redirect(
                    "/feed"
                );
            }

            if (
                content.length > 500
            ) {
                return res.status(400).send(
                    "post is too long"
                );
            }

            if (
                communityId !== null &&
                !Number.isInteger(
                    communityId
                )
            ) {
                return res.status(400).send(
                    "invalid community"
                );
            }

            let attachmentUrl =
                null;

            let attachmentName =
                null;

            if (req.file) {

                attachmentUrl =
                    await saveUploadedFile(
                        req.file,
                        `posts/${req.user.id}`
                    );

                attachmentName =
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
                    communityId,
                    content || "",
                    attachmentUrl,
                    attachmentName
                ]
            );

            res.redirect(
                req.get("referer") ||
                "/feed"
            );

        } catch (error) {

            console.error(
                "create post error:"
            );

            console.error(error);

            res.status(500).send(
                "could not create post"
            );
        }
    }
);


/* =========================================================
   likes
   ========================================================= */

app.post(
    "/posts/:id/like",
    requireLogin,
    async (req, res) => {

        try {

            const postId =
                Number(
                    req.params.id
                );

            if (
                !Number.isInteger(postId)
            ) {
                return res.status(400).send(
                    "invalid post"
                );
            }

            const existing =
                await pool.query(
                    `
                    select id
                    from likes
                    where user_id = $1
                    and post_id = $2
                    limit 1
                    `,
                    [
                        req.user.id,
                        postId
                    ]
                );

            if (
                existing.rows.length
            ) {

                await pool.query(
                    `
                    delete from likes
                    where user_id = $1
                    and post_id = $2
                    `,
                    [
                        req.user.id,
                        postId
                    ]
                );

            } else {

                await pool.query(
                    `
                    insert into likes (
                        user_id,
                        post_id
                    )
                    values (
                        $1,
                        $2
                    )
                    on conflict do nothing
                    `,
                    [
                        req.user.id,
                        postId
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
   comments
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
                        u.profile_picture,
                        u.profile_image_url,
                        c.name as community_name
                    from posts p
                    join users u
                        on u.id = p.user_id
                    left join communities c
                        on c.id = p.community_id
                    where p.id = $1
                    limit 1
                    `,
                    [
                        req.params.id
                    ]
                );

            if (
                !post.rows.length
            ) {
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
                        u.display_name,
                        u.profile_picture,
                        u.profile_image_url
                    from comments cm
                    join users u
                        on u.id = cm.user_id
                    where cm.post_id = $1
                    order by cm.created_at asc
                    `,
                    [
                        req.params.id
                    ]
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

            if (
                content.length > 300
            ) {
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
                        where id = $2
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

            const profileResult =
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
                    where username = $1
                    limit 1
                    `,
                    [
                        username
                    ]
                );

            if (
                !profileResult.rows.length
            ) {
                return res.status(404).send(
                    "user not found"
                );
            }

            const profile =
                profileResult.rows[0];

            if (
                !profile.profile_picture &&
                profile.profile_image_url
            ) {
                profile.profile_picture =
                    profile.profile_image_url;
            }

            const postsResult =
                await pool.query(
                    `
                    select
                        p.*,
                        c.name as community_name,
                        u.username,
                        u.display_name,
                        u.profile_picture,
                        u.profile_image_url,

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

                    join users u
                        on u.id = p.user_id

                    where p.user_id = $1

                    order by p.created_at desc

                    limit 100
                    `,
                    [
                        profile.id
                    ]
                );

            res.render(
                "profile",
                {
                    user: req.user,
                    profile,
                    posts:
                        postsResult.rows
                }
            );

        } catch (error) {

            console.error(
                "profile error:"
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

            const displayName =
                String(
                    req.body.display_name || ""
                )
                    .trim()
                    .slice(0, 100);

            const bio =
                String(
                    req.body.bio || ""
                )
                    .trim()
                    .slice(0, 1000);

            let profilePicture =
                req.user.profile_picture ||
                req.user.profile_image_url ||
                null;

            if (req.file) {

                profilePicture =
                    await saveUploadedFile(
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
                    displayName ||
                        req.user.username,

                    bio,

                    profilePicture,

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

            res.status(500).render(
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
                )
                    .trim()
                    .slice(0, 500);

            if (
                !/^[a-z0-9_]{2,50}$/.test(
                    name
                )
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
   community
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

            const communityResult =
                await pool.query(
                    `
                    select
                        c.*,
                        u.username
                            as creator_username
                    from communities c
                    left join users u
                        on u.id = c.creator_id
                    where c.name = $1
                    limit 1
                    `,
                    [
                        name
                    ]
                );

            if (
                !communityResult.rows.length
            ) {
                return res.status(404).send(
                    "community not found"
                );
            }

            const community =
                communityResult.rows[0];

            const postsResult =
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
                        ) as comments

                    from posts p

                    join users u
                        on u.id = p.user_id

                    where p.community_id = $1

                    order by p.created_at desc

                    limit 100
                    `,
                    [
                        community.id
                    ]
                );

            res.render(
                "community",
                {
                    user: req.user,
                    community,
                    posts:
                        postsResult.rows
                }
            );

        } catch (error) {

            console.error(
                "community error:"
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

                const usersResult =
                    await pool.query(
                        `
                        select
                            id,
                            username,
                            display_name,
                            profile_picture,
                            profile_image_url
                        from users
                        where username ilike $1
                        or display_name ilike $1
                        order by username
                        limit 25
                        `,
                        [
                            search
                        ]
                    );

                const communitiesResult =
                    await pool.query(
                        `
                        select
                            c.*,
                            count(p.id)::integer
                                as post_count
                        from communities c
                        left join posts p
                            on p.community_id = c.id
                        where c.name ilike $1
                        or c.description ilike $1
                        group by c.id
                        order by c.name
                        limit 25
                        `,
                        [
                            search
                        ]
                    );

                const postsResult =
                    await pool.query(
                        `
                        select
                            p.id,
                            p.content,
                            p.created_at,
                            p.attachment_url,
                            p.attachment_name,
                            u.username,
                            u.display_name,
                            u.profile_picture,
                            u.profile_image_url,
                            c.name
                                as community_name
                        from posts p
                        join users u
                            on u.id = p.user_id
                        left join communities c
                            on c.id = p.community_id
                        where p.content ilike $1
                        order by p.created_at desc
                        limit 50
                        `,
                        [
                            search
                        ]
                    );

                users =
                    usersResult.rows;

                communities =
                    communitiesResult.rows;

                posts =
                    postsResult.rows;
            }

            res.render(
                "search",
                {
                    user: req.user,
                    query,
                    users,
                    communities,
                    posts
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
                    order by created_at desc
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
                    order by p.created_at desc
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
                    order by c.created_at desc
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
                [
                    req.params.id
                ]
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

            const targetId =
                Number(
                    req.params.id
                );

            if (
                targetId ===
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
                [
                    targetId
                ]
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
                status: "ok",
                database: "connected",
                storage:
                    supabase
                        ? "supabase"
                        : "local"
            });

        } catch (error) {

            console.error(
                "health check error:"
            );

            console.error(error);

            res.status(500).json({
                status: "error",
                database: "disconnected"
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
   multer / global error handler
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
                return res
                    .status(400)
                    .send(
                        "file is too large. maximum size is 15mb"
                    );
            }

            if (
                error.code ===
                "LIMIT_UNEXPECTED_FILE"
            ) {
                return res
                    .status(400)
                    .send(
                        "unexpected upload field"
                    );
            }
        }

        if (
            error.message ===
            "only image files are allowed"
        ) {
            return res
                .status(400)
                .send(
                    "only png, jpeg, gif, and webp images are allowed"
                );
        }

        res
            .status(500)
            .send(
                "internal server error"
            );
    }
);


/* =========================================================
   start
   ========================================================= */

initializeDatabase()
    .then(() => {

        app.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    `helloworld running on port ${PORT}`
                );

                if (supabase) {

                    console.log(
                        `storage: supabase bucket "${STORAGE_BUCKET}"`
                    );

                } else {

                    console.log(
                        "storage: local /uploads fallback"
                    );
                }
            }
        );

    })
    .catch((error) => {

        console.error(
            "failed to initialize database:"
        );

        console.error(error);

        process.exit(1);
    });