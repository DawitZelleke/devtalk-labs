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
