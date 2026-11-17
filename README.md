# DevTalk Security Lab

Security investigation and remediation of a supplied PHP and SQLite forum for CST8265 Labs 4 and 5. The original forum was provided for the course; my contribution is the vulnerability analysis, patches, and verification documented here.

## Review the work

- [Patch log](PATCH-LOG.md): nine finding categories with root causes, changed files, and before-and-after checks.
- [Shared security helpers](src/helpers.php): CSRF validation, session handling, password verification, and output sanitization.
- [Verification screenshots](docs/screenshots/): evidence referenced by the patch log.

The patch log records 18 exploit checks and 16 normal-use checks. These are documented manual regression checks, not an automated suite or an independent security assessment.

## Engineering decisions

Parameterized queries keep input separate from SQL. Ownership checks protect changes to other users' records. CSRF tokens and POST-only handlers protect state-changing operations. Password hashing and session ID regeneration strengthen account handling. Server-side image fetching was removed to eliminate that SSRF entry point.

## Scope

This is an educational application for local evaluation. Its known demonstration credentials and vulnerable baseline are intentional lab materials. The documented checks do not establish that every possible vulnerability has been eliminated.

## Requirements

- PHP 8.1 or newer (with the `pdo_sqlite` extension — bundled with most PHP builds)
- [Composer](https://getcomposer.org/)

Check your PHP version and extension:

```bash
php -v
php -m | grep -i sqlite
```

## Setup

Clone the repository, then run commands from its root:

```bash
git clone https://github.com/DawitZelleke/devtalk-labs.git
cd devtalk-labs
```

Use a disposable local database for this lab:

```bash
# 1. Build and seed the database
composer reset-db

# 2. Start the development server
composer start
```

Then open <http://localhost:8000> in your browser.

To wipe any changes and start fresh at any time, run `composer reset-db` again.

## Sample accounts

The seeded database includes these accounts (username / password):

| Username | Password       | Role  |
|----------|----------------|-------|
| admin    | `Sup3rSecret!` | admin |
| alice    | `password123`  | user  |
| bob      | `hunter2`      | user  |
| carol    | `letmein2024`  | user  |

You can also register your own account from the **Register** page.

## Features

- Public homepage listing forum topics, newest first
- Read topics and comments without logging in
- Register and log in
- Create topics (title + body; HTML and images are supported)
- Edit and delete topics
- Comment on topics and delete comments
- User profiles with a list of their topics
- Topic search
- Image preview for topics that reference an image URL

## Project layout

```
forum/
├── composer.json          # defines `composer start` and `composer reset-db`
├── public/                # web root (point your server here)
│   ├── index.php          # homepage
│   ├── topic.php          # view a topic + comments
│   ├── login.php / register.php / logout.php
│   ├── create_topic.php / edit_topic.php / delete_topic.php
│   ├── add_comment.php / delete_comment.php
│   ├── search.php         # topic search
│   ├── profile.php        # user profile
│   ├── fetch_image.php    # disabled server-side fetch endpoint
│   └── assets/            # CSS and images
├── src/                   # config, DB connection, shared helpers
└── database/              # schema + build/seed script (SQLite file is generated)
```

## Troubleshooting

- **`php: command not found`** — install PHP (e.g. `brew install php` on macOS).
- **Database errors on first load** — run `composer reset-db` before `composer start`.
- **Port 8000 in use** — edit the `start` script in `composer.json` to use another port.
