/* =========================================================
   database initialization
   ========================================================= */

async function initializeDatabase() {

    console.log("initializing database...");

    /* =====================================================
       sessions
       ===================================================== */

    await pool.query(`
        create table if not exists user_sessions (
            sid varchar not null collate "default",

            sess json not null,

            expire timestamp(6)
                without time zone
                not null
        )
    `);

    await pool.query(`
        create unique index if not exists user_sessions_pkey
        on user_sessions (sid)
    `);

    await pool.query(`
        create index if not exists user_sessions_expire_idx
        on user_sessions (expire)
    `);


    /* =====================================================
       users
       ===================================================== */

    await pool.query(`
        create table if not exists users (
            id serial primary key,

            username varchar(32)
                unique
                not null,

            email varchar(255)
                unique
                not null,

            password_hash text
                not null,

            display_name varchar(100),

            bio text,

            profile_picture text,

            is_admin boolean
                not null
                default false,

            created_at timestamptz
                not null
                default now()
        )
    `);


    /* =====================================================
       communities
       ===================================================== */

    await pool.query(`
        create table if not exists communities (
            id serial primary key,

            name varchar(50)
                unique
                not null,

            description text,

            creator_id integer
                references users(id)
                on delete set null,

            created_at timestamptz
                not null
                default now()
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

            created_at timestamptz
                not null
                default now(),

            unique (
                community_id,
                user_id
            )
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

            content text
                not null,

            attachment_url text,

            attachment_name text,

            created_at timestamptz
                not null
                default now()
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

            created_at timestamptz
                not null
                default now(),

            unique (
                user_id,
                post_id
            )
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

            content text
                not null,

            created_at timestamptz
                not null
                default now()
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

            created_at timestamptz
                not null
                default now(),

            unique (
                follower_id,
                following_id
            )
        )
    `);


    /* =====================================================
       indexes
       ===================================================== */

    await pool.query(`
        create index if not exists posts_created_at_idx
        on posts (created_at desc)
    `);

    await pool.query(`
        create index if not exists posts_user_id_idx
        on posts (user_id)
    `);

    await pool.query(`
        create index if not exists posts_community_id_idx
        on posts (community_id)
    `);

    await pool.query(`
        create index if not exists comments_post_id_idx
        on comments (post_id)
    `);

    await pool.query(`
        create index if not exists likes_post_id_idx
        on likes (post_id)
    `);

    await pool.query(`
        create index if not exists likes_user_id_idx
        on likes (user_id)
    `);

    await pool.query(`
        create index if not exists follows_follower_id_idx
        on follows (follower_id)
    `);

    await pool.query(`
        create index if not exists follows_following_id_idx
        on follows (following_id)
    `);


    /* =====================================================
       finished
       ===================================================== */

    console.log("database initialized successfully");
}
