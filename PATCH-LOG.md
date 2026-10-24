# DevTalk — Lab 5 Patch Log

Dawit Zelleke | CST8265 | 23 October 2026
Repository: https://github.com/DawitZelleke/devtalk-labs
Baseline (vulnerable) commit: `8f690f8`
Tested locally on PHP 8.3 + SQLite. Exploits were re-run against the running
dev server (`php -S 127.0.0.1:8000 -t public`) before and after each patch.
Screenshots of each blocked exploit are in `docs/screenshots/`.

Each patch below maps to the correspondingly numbered finding in the Lab 4
Vulnerability Log.

---

## Patch #1 — Parameterize login and search (A05 Injection — SQLi)

**Lab 4 finding:** #1 — SQL injection in login and search.

**Root cause.** `login.php` built its query by interpolating the raw
`$username`/`$password` into `WHERE username = '$username' AND password =
'$password'`, and `search.php` interpolated `$q` into
`... LIKE '%$q%'`. User input was parsed as SQL, so a crafted username could
comment out the password check and a `UNION SELECT` in the search box could
read arbitrary columns (including the credential column).

**Exploit confirmed on current code.**
- Login auth bypass: a username that closes the string literal and comments
  out the rest authenticated as `admin` without the password → the following
  page showed the logged-in navbar.
- Search UNION read: a `UNION SELECT id,username,password FROM users` payload
  returned the seeded admin credential in the results.

**Fix.**
- `login.php` now runs `SELECT * FROM users WHERE username = ?` as a prepared
  statement with a bound parameter, fetches the row, and checks the password
  with a new `verify_user_password()` helper (`password_verify()` for hashed
  records; constant-time compare for any legacy plaintext record — storage is
  migrated to hashes in Patch #6). No user input reaches the SQL text.
- `search.php` now uses a prepared statement with bound `LIKE` parameters
  (`title LIKE ? OR body LIKE ?`); the `%` wildcards wrap the *bound value*,
  not the query string.

**Re-test (exploit fails).**
- Auth-bypass payload → "Invalid username or password."; navbar stays
  logged-out. `docs/screenshots/01a-login-sqli-blocked.png`.
- UNION payload → treated as a literal search term; zero results and no
  credential disclosed. `docs/screenshots/01b-search-union-blocked.png`.

**Normal use still works.** `alice / password123` logs in (HTTP 302 →
logged-in navbar); searching `CSS` returns the "Favourite CSS layout tricks"
topic.

---

## Patch #2 — Encode reflected text, sanitize stored HTML (A05 Injection — XSS)

**Lab 4 finding:** #2 — reflected and stored cross-site scripting.

**Root cause.** `search.php` echoed the raw query term (`Results for: <?= $q ?>`),
and `topic.php` printed `$topic['body']` and each `$c['body']` with no encoding
or filtering. Attacker-controlled markup was sent to the browser verbatim, so an
`<img onerror=…>` (or `<script>`) ran as script — reflected in search, stored in
topics and comments.

**Exploit confirmed on current code.** An `<img src=x onerror="document.title=…">`
term rendered as live markup in the search results, and the same body stored in a
topic/comment executed when the page was viewed.

**Fix.**
- Reflected: the search term is now printed through `htmlspecialchars()`
  (it was already escaped in the input `value`).
- Stored: topic and comment bodies are passed through a new `sanitize_html()`
  helper before output. It parses the HTML with `DOMDocument` and rebuilds it
  against a strict allowlist — a small set of formatting tags (`p`, `strong`,
  `em`, `code`, `ul/ol/li`, headings, `a`, `img`, …), only `href`/`src`/`alt`/
  `title` attributes, and only `http`/`https`/`mailto`/relative URLs (via
  `url_is_safe()`). Every unknown tag, every `on*` handler and every unsafe
  scheme (`javascript:`, `data:`) is removed.

**Re-test (exploit fails).**
- Reflected: the payload is fully HTML-encoded (`&lt;img … onerror=&quot;…`),
  zero unescaped `<img>` tags; the page title never changes.
  `docs/screenshots/02a-reflected-xss-blocked.png`.
- Stored: the saved `<img onerror>`/`<script>` are stripped; the browser title
  stays `XSS probe (stored) · DevTalk Forum` — no script ran.
  `docs/screenshots/02b-stored-xss-blocked.png`.

**Normal use still works.** Post formatting survives sanitising — the probe's
`<strong>bold</strong>` and the seeded welcome topic's `<strong>` text and
`assets/img/welcome.png` image all still render.

---

## Patch #3 — Enforce object ownership before mutation (A01 Broken Access Control — IDOR)

**Lab 4 finding:** #3 — missing object ownership authorization.

**Root cause.** `edit_topic.php`, `delete_topic.php` and `delete_comment.php`
checked only `require_login()` — any logged-in user could act on any object id.
`profile.php` updated `users` using the **submitted** `user_id`, so a user could
overwrite anyone's bio.

**Exploit confirmed on current code.** Logged in as `alice`, requests against
Bob's topic/comment and the admin's topic modified or deleted them, and a
`profile.php` POST with `user_id=3` rewrote Bob's bio.

**Fix.** Every mutation now authorizes the loaded record against the
authenticated user, server-side, before changing anything:
- `edit_topic.php` — owner-only; non-owners get `403`.
- `delete_topic.php` / `delete_comment.php` — load the record first; allow the
  owner, or an admin (moderation); otherwise `403`.
- `profile.php` — the bio update targets `current_user_id()`; the request's
  `user_id` is ignored, so a user can only edit their own bio.
New helpers `current_user_id()`, `current_user_is_admin()` and `forbid()` back
these checks.

**Re-test (exploit fails).** As `alice`: `GET`/`POST edit_topic?id=3` → `403`,
Bob's title unchanged; `profile.php` POST with `user_id=3` → Bob's bio
unchanged, only Alice's own bio updated; `delete_comment?id=2` and
`delete_topic?id=4` → `403`, both records still present.
`docs/screenshots/03-idor-edit-forbidden.png`.

**Normal use still works.** Alice edits her own topic (HTTP 302, title updated);
the admin moderates/deletes another user's topic (HTTP 302, removed).

---

## Patch #4 — CSRF tokens and POST-only state changes (A01 Broken Access Control — CSRF)

**Lab 4 finding:** #4 — CSRF and unsafe GET actions.

**Root cause.** No POST handler carried an anti-forgery token, so any page
could submit a state change using the victim's cookie. Worse,
`delete_topic.php`, `delete_comment.php` and `logout.php` mutated state on a
plain `GET`, so a single `<img>`/link could trigger them.

**Exploit confirmed on current code.** A tokenless POST to `create_topic.php`
with a valid session was accepted (302), and `GET delete_topic.php?id=…`
deleted the topic.

**Fix.**
- New helpers `csrf_token()`, `csrf_field()`, `verify_csrf()` issue a 32-byte
  random per-session token and compare it with `hash_equals()`.
- Every POST form embeds `csrf_field()` (login, register, create/edit topic,
  add comment, profile bio, delete topic, delete comment, logout), and every
  POST handler calls `verify_csrf()` → `403` on a missing/invalid token.
- `delete_topic.php`, `delete_comment.php` and `logout.php` now call
  `require_post()` (→ `405` on GET) and read their ids from `$_POST`. The
  topic/comment "Delete" and nav "Log out" controls are now token-bearing POST
  forms.

**Re-test (exploit fails).**
- Tokenless POST to `create_topic.php` → `403`; topic count unchanged.
- Tampered-token POST → "Forbidden" page, no topic created.
  `docs/screenshots/04a-csrf-token-rejected.png`.
- `GET delete_topic.php` / `delete_comment.php` / `logout.php` → `405`; records
  preserved and the session stays logged in.
  `docs/screenshots/04b-delete-get-405.png`.

**Normal use still works.** With valid tokens: login, create topic, add
comment, delete own topic and logout all succeed (HTTP 302).

---

## Patch #5 — Remove arbitrary server-side URL fetching (A01 Broken Access Control — SSRF)

**Lab 4 finding:** #5 — server-side request forgery and local file disclosure.

**Root cause.** `fetch_image.php` passed the user-supplied `url` straight to
`file_get_contents()` with redirects enabled. PHP stream wrappers meant the
server would read `file://` paths and request any host the user named,
including loopback/internal services, and return the bytes.

**Exploit confirmed on current code.** With the original file restored
temporarily: a `file://` URL to a local sentinel fixture returned
`LAB5_LOCAL_FILE_SENTINEL` (HTTP 200), and `http://127.0.0.1:8001/private`
caused one request to a harmless local test listener and returned its internal
marker (HTTP 200).

**Fix.** The server no longer fetches user-supplied URLs at all:
- A scheme-less relative path is served only if `realpath()` resolves it to an
  image file inside `public/assets` or `public/uploads` (blocks `../`
  traversal and non-image files).
- An `https` URL whose host is on a fixed allowlist of image hosts is returned
  to the browser as a `302` redirect, so the browser fetches it directly.
- Anything else (`file://`, `http://`, loopback, other hosts) → `400`.

**Re-test (exploit fails).** `file://` → `400`, no sentinel;
loopback URL → `400`, no marker, **0** requests reached the listener.
`docs/screenshots/05a-ssrf-file-uri-blocked.png`,
`docs/screenshots/05b-ssrf-loopback-blocked.png`. A `../src/config.php`
traversal also returns `400`.

**Normal use still works.** `assets/img/welcome.png` is served (HTTP 200,
`image/png`); an approved `https://upload.wikimedia.org/…` image returns a 302
redirect to the browser.

---

## Patch #6 — Hash passwords with password_hash() (A04 Cryptographic Failures)

**Lab 4 finding:** #6 — plaintext password storage.

**Root cause.** `database/build_db.php` inserted the seed passwords unchanged
and `register.php` inserted `$password` unchanged, so the `users.password`
column held every password in clear text. Any database read (SQLi, a leaked
backup, local access) exposed real credentials.

**Exploit confirmed on current code.** After seeding and registering
`labtester / LabTestPass123!`, all 5 passwords were present verbatim in
`users.password` and in the raw `forum.sqlite` file.

**Fix.**
- `build_db.php` and `register.php` store `password_hash($password,
  PASSWORD_DEFAULT)` (salted, adaptive bcrypt).
- `verify_user_password()` now accepts **only** hashes via `password_verify()`.
  The temporary plaintext path from Patch #1 is removed, and hashes are
  upgraded with `password_needs_rehash()` when PHP's default changes.
- New `database/migrate_passwords.php` hashes any plaintext rows in an existing
  database once, then runs `VACUUM` so old values are not left in free pages.
- Removed the schema comment that described plaintext storage.

**Re-test (exploit fails).** Rebuilt DB + new registration: 0 plaintext rows,
0 plaintext matches in the raw database file; values are `$2y$10$…` hashes.
A legacy plaintext row can no longer log in until the migration hashes it.
`docs/screenshots/06-passwords-hashed.png`.

**Normal use still works.** `admin`, `alice`, `bob`, `carol` and the newly
registered `labtester` all log in; a wrong password is rejected. The sample
credentials stay limited to this local lab.
