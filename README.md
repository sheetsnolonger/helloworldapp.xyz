# helloworld

a small, welcoming social app built with node.js, express, ejs, sqlite, and sessions.

all user-facing text is lowercase.

## local setup

requires node.js 22 or newer.

```bash
npm install
cp .env.example .env
npm start
```

open:

http://localhost:3000

## github + render

1. create a github repository named `helloWorld`.
2. upload all files from this project to the repository.
3. connect the repository to render.
4. render can use the included `render.yaml`.
5. the render disk keeps the sqlite database and session data persistent across deploys.

do not upload `.env` to github.

## important

sqlite is appropriate for a small personal/community deployment. for a large public social network, move the database to postgresql and use a shared session store.

## health check

`/health` returns a small json response and is used by render to check that the app is running.
