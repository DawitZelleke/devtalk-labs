# DevTalk — Lab 5 Patch Log

Dawit Zelleke | CST8265 | 23 October 2026
Repository: https://github.com/DawitZelleke/devtalk-labs
Baseline (vulnerable) commit: `8f690f8`
Tested locally on PHP 8.3 + SQLite. Exploits were re-run against the running
dev server (`php -S 127.0.0.1:8000 -t public`) before and after each patch.
Screenshots of each blocked exploit are in `docs/screenshots/`.

Each patch below maps to the correspondingly numbered finding in the Lab 4
Vulnerability Log.

## Summary

| Patch | Lab 4 finding | OWASP 2025 | Files changed | Result |
|---|---|---|---|---|
| #1 | SQL injection (login, search) | A05 Injection | `login.php`, `search.php`, `helpers.php` | Prepared statements, bound params |
| #2 | Reflected + stored XSS | A05 Injection | `search.php`, `topic.php`, `helpers.php` | Output encoding + HTML allowlist |
| #3 | IDOR (edit/delete/profile) | A01 Broken Access Control | `edit_topic.php`, `delete_topic.php`, `delete_comment.php`, `profile.php`, `helpers.php` | Ownership checks → 403 |
| #4 | CSRF + unsafe GET | A01 Broken Access Control | all POST forms/handlers, `logout.php`, `helpers.php` | Session tokens → 403; GET → 405 |
| #5 | SSRF + local file read | A01 Broken Access Control | `fetch_image.php` | No server-side fetch; 400 |
| #6 | Plaintext passwords | A04 Cryptographic Failures | `build_db.php`, `register.php`, `helpers.php`, `schema.sql`, `migrate_passwords.php` | `password_hash`/`password_verify` |
| #7 | Session fixation, no HttpOnly | A07 Authentication Failures | `helpers.php`, `login.php`, `register.php` | ID regenerated; HttpOnly + SameSite |
| #8 | DB exception disclosure | A10 Exceptional Conditions | `search.php`, `login.php`, `register.php`, `helpers.php` | Generic messages; details logged |
| #9 | Public debug output, array params | A02 Security Misconfiguration | `config.php`, `errors.php`, input readers | display_errors off; 400 on bad shape |

**Final regression (after Patch #9):** all 18 exploit checks from findings #1–#9
fail as expected, and all 16 normal-use checks pass: login for every seeded
account, search, post formatting, create/edit/delete topic, add/delete comment,
update own bio, admin moderation, register, logout, and bundled image preview.
**34/34 passed.**

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

---

## Patch #7 — Regenerate session at login, harden session cookie (A07 Authentication Failures)

**Lab 4 finding:** #7 — session fixation and unprotected session cookies.

**Root cause.** `src/helpers.php` called a bare `session_start()`, so the
`PHPSESSID` cookie had no `HttpOnly`/`SameSite` flags and PHP accepted any
session ID the client offered. `login.php` and `register.php` then set
`$_SESSION['user_id']` on that same ID. An ID that existed before login (or one
an attacker planted) became an authenticated session.

**Exploit confirmed on current code.** `GET login.php`, keep the cookie, log in
as Alice: `PHPSESSID` was identical before and after login, and the pre-login
ID was itself a logged-in session. The cookie lacked `HttpOnly`/`SameSite`, and
an arbitrary attacker-chosen ID was accepted as-is.

**Fix.**
- `session_start()` now runs with `use_strict_mode` (unknown IDs are
  replaced), `use_only_cookies`, `cookie_httponly`, `cookie_samesite=Lax`, and
  `cookie_secure` when the request is HTTPS.
- New `login_user()` helper calls `session_regenerate_id(true)` (deleting the
  old session), sets `user_id`, and rotates the CSRF token. It's used by both
  login and registration.

**Re-test (exploit fails).** The session ID changes at login; the pre-login ID
is no longer logged in; `Set-Cookie` carries `HttpOnly; SameSite=Lax`; an
attacker-chosen ID is replaced with a fresh one; in the browser
`document.cookie` cannot see `PHPSESSID`.
`docs/screenshots/07-session-regenerated-httponly.png`.

**Normal use still works.** In a real browser Alice logs in, stays logged in
across pages, and logs out normally. Registration still logs the new user in.

---

## Patch #8 — Generic error messages, details logged server-side (A10 Mishandling of Exceptional Conditions)

**Lab 4 finding:** #8 — database exception information disclosure.

**Root cause.** The `catch (PDOException $e)` blocks in `search.php`,
`login.php` and `register.php` copied `$e->getMessage()` (and originally the
SQL text) into the page. `login.php` and `register.php` printed it without
encoding. Any database failure exposed SQLSTATE codes, driver messages and
table/column names, even with `display_errors` off.

**Exploit confirmed on current code.** Patch #1 already stopped the Lab 4
`' UNION SELECT 1 --` payload from causing a SQL error, so I triggered two real
`PDOException`s instead. Registering the existing username `alice` showed
`SQLSTATE[23000]: Integrity constraint violation: 19 UNIQUE constraint failed:
users.username`. A search while the `topics` table was temporarily renamed
showed `SQLSTATE[HY000]: General error: 1 no such table: topics`.

**Fix.**
- New `log_exception()` helper writes the exception class, message, file and
  line to the server-side PHP error log.
- Each catch block now logs and shows a fixed, generic message ("Search is
  temporarily unavailable…" with HTTP 500, "Login is temporarily
  unavailable…", "Could not create the account…").
- Error messages in `login.php`/`register.php` are now printed through
  `htmlspecialchars()`.

**Re-test (exploit fails).** Duplicate registration shows only the generic
message; the forced search failure returns 500 with the generic message; no
`SQLSTATE`, constraint, table or column names appear in any response. The
details do appear in the server log.
`docs/screenshots/08a-register-error-generic.png`,
`docs/screenshots/08b-db-errors-generic.png`.

**Normal use still works.** A new user (`newuser8`) registers (HTTP 302), and
searching `PDO` returns the matching topic.

---

## Patch #9 — Disable public diagnostics, validate input shape (A02 Security Misconfiguration)

**Lab 4 finding:** #9 — public debug output and malformed input handling.

**Root cause.** Two problems combined:
1. `src/config.php` set `display_errors` and `display_startup_errors` to `1`,
   so every PHP warning, fatal error and uncaught exception was printed to the
   visitor, along with server file paths and line numbers.
2. Pages assumed query parameters were strings. PHP turns `q[]=x` into an
   array, which caused an "Array to string conversion" warning and an uncaught
   `TypeError`. The page still returned HTTP 200.

**Exploit confirmed on current code.** `search.php?q[]=x` returned HTTP 200
with a `Warning:` and a `Fatal error: Uncaught TypeError … in
/home/claude/devtalk-labs/public/search.php`. The same thing happened with
`topic.php?id[]=1`, `profile.php?id[]=1` and `fetch_image.php?url[]=x`.

**Fix.**
- New `src/errors.php` (loaded by `config.php`) sets `display_errors=0` and
  `display_startup_errors=0`, enables `log_errors`, and writes to
  `logs/php-error.log`. That folder is outside the web root and git-ignored.
- A global `set_exception_handler()` boundary logs any uncaught exception and
  returns a generic HTTP 500 page.
- `request_string()` reads a parameter and calls `bad_request()` (HTTP 400,
  "Invalid request parameter.") if the value is an array or too long. It's
  used for `q`, `id`, `url` and the login/registration fields.

**Re-test (exploit fails).** `search.php?q[]=x` → HTTP 400 "Invalid request
parameter." with no PHP output. `topic.php`, `profile.php` and
`fetch_image.php` with array parameters → 400, with zero diagnostic lines and
zero server-path leaks. An unexpected `TypeError` elsewhere (`title[]=x` on
create topic) → generic 500, logged privately.
`docs/screenshots/09a-array-param-400.png`,
`docs/screenshots/09b-malformed-input-400.png`.

**Normal use still works.** Ordinary searches (`CSS`), topic and profile pages,
the homepage and bundled image previews all return 200 with the expected
content.
