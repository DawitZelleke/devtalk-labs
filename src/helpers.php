<?php
require_once __DIR__ . '/db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function is_logged_in(): bool
{
    return isset($_SESSION['user_id']);
}

function current_user(): ?array
{
    if (!is_logged_in()) {
        return null;
    }
    $stmt = db()->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    return $user ?: null;
}

function require_login(): void
{
    if (!is_logged_in()) {
        header('Location: login.php');
        exit;
    }
}

function current_user_id(): ?int
{
    return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
}

function current_user_is_admin(): bool
{
    $u = current_user();
    return $u !== null && (int) ($u['is_admin'] ?? 0) === 1;
}

/** Send a 403 page and stop. Used when an authenticated user is not
 *  authorized to act on the requested object. */
function forbid(string $msg = 'You are not allowed to do that.'): void
{
    http_response_code(403);
    render_header('Forbidden');
    echo '<div class="alert alert-danger">' . htmlspecialchars($msg) . '</div>';
    render_footer();
    exit;
}

/**
 * Verify a submitted password against a stored user record.
 * Hashed records are checked with password_verify(); any legacy plaintext
 * record (pre-migration seed) is compared in constant time. Password storage
 * itself is migrated to hashes in Patch #6.
 */
function verify_user_password(string $password, array $user): bool
{
    $stored = (string) ($user['password'] ?? '');
    $info = password_get_info($stored);
    if (!empty($info['algo'])) {
        return password_verify($password, $stored);
    }
    return hash_equals($stored, $password);
}

/**
 * Is a URL safe to place in an href/src? Allows http/https/mailto and
 * scheme-less relative URLs; rejects javascript:, data:, vbscript:, etc.
 */
function url_is_safe(string $url): bool
{
    $url = trim($url);
    if ($url === '' || preg_match('/[\x00-\x1F\x7F]/', $url)) {
        return false;
    }
    if (preg_match('#^([a-z][a-z0-9+.\-]*):#i', $url, $m)) {
        return in_array(strtolower($m[1]), ['http', 'https', 'mailto'], true);
    }
    return true; // relative / anchor
}

/**
 * Sanitize user-supplied HTML against a strict tag/attribute allowlist.
 * Keeps basic formatting (paragraphs, bold, lists, code, links, images) but
 * drops every unknown tag and every attribute not on the allowlist, including
 * all on* event handlers and unsafe URL schemes. Defeats stored XSS while
 * preserving the forum's "HTML allowed" posting feature.
 */
function sanitize_html(string $html): string
{
    $html = trim($html);
    if ($html === '') {
        return '';
    }

    $allowed = [
        'p' => [], 'br' => [], 'strong' => [], 'b' => [], 'em' => [], 'i' => [],
        'u' => [], 'code' => [], 'pre' => [], 'blockquote' => [], 'span' => [],
        'ul' => [], 'ol' => [], 'li' => [],
        'h1' => [], 'h2' => [], 'h3' => [], 'h4' => [], 'h5' => [], 'h6' => [],
        'a' => ['href', 'title'],
        'img' => ['src', 'alt', 'title'],
    ];

    $doc = new DOMDocument();
    libxml_use_internal_errors(true);
    $doc->loadHTML(
        '<?xml encoding="UTF-8"><div id="__root">' . $html . '</div>',
        LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD
    );
    libxml_clear_errors();

    $root = null;
    foreach ($doc->childNodes as $n) {
        if ($n instanceof DOMElement) {
            $root = $n;
            break;
        }
    }
    if ($root === null) {
        return htmlspecialchars(strip_tags($html));
    }

    $clean = function (DOMNode $node) use (&$clean, $allowed) {
        foreach (iterator_to_array($node->childNodes) as $child) {
            if ($child instanceof DOMText) {
                continue;
            }
            if (!($child instanceof DOMElement)) {
                $node->removeChild($child); // comments, PIs, etc.
                continue;
            }
            $tag = strtolower($child->tagName);
            if (!array_key_exists($tag, $allowed)) {
                $node->removeChild($child); // drop unknown element + subtree
                continue;
            }
            foreach (iterator_to_array($child->attributes) as $attr) {
                $name = strtolower($attr->name);
                if (!in_array($name, $allowed[$tag], true)) {
                    $child->removeAttribute($attr->name);
                    continue;
                }
                if (($tag === 'a' && $name === 'href') || ($tag === 'img' && $name === 'src')) {
                    if (!url_is_safe($attr->value)) {
                        $child->removeAttribute($attr->name);
                    }
                }
            }
            $clean($child);
        }
    };
    $clean($root);

    $out = '';
    foreach (iterator_to_array($root->childNodes) as $c) {
        $out .= $doc->saveHTML($c);
    }
    return $out;
}

function render_header(string $title = APP_NAME): void
{
    $user = current_user();
?>
    <!doctype html>
    <html lang="en">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title><?= htmlspecialchars($title) ?> · <?= APP_NAME ?></title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="assets/app.css" rel="stylesheet">
    </head>

    <body class="bg-body-tertiary">
        <nav class="navbar navbar-expand-lg bg-dark" data-bs-theme="dark">
            <div class="container">
                <a class="navbar-brand fw-semibold" href="index.php">💬 <?= APP_NAME ?></a>
                <div class="d-flex align-items-center gap-2">
                    <form class="d-flex me-2" role="search" action="search.php" method="get">
                        <input class="form-control form-control-sm" type="search" name="q"
                            placeholder="Search topics…" aria-label="Search">
                    </form>
                    <?php if ($user): ?>
                        <a class="btn btn-sm btn-primary" href="create_topic.php">New Topic</a>
                        <a class="btn btn-sm btn-outline-light" href="profile.php?id=<?= $user['id'] ?>">
                            <?= htmlspecialchars($user['username']) ?>
                        </a>
                        <a class="btn btn-sm btn-outline-light" href="logout.php">Log out</a>
                    <?php else: ?>
                        <a class="btn btn-sm btn-outline-light" href="login.php">Log in</a>
                        <a class="btn btn-sm btn-primary" href="register.php">Register</a>
                    <?php endif; ?>
                </div>
            </div>
        </nav>
        <main class="container py-4">
        <?php
    }

    function render_footer(): void
    {
        ?>
        </main>
        <footer class="container text-center text-body-secondary py-4 small">
            <?= APP_NAME ?> — CST8265 lab application. For educational use only.
        </footer>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>

    </html>
<?php
    }

    function fmt_date(?string $ts): string
    {
        if (!$ts) {
            return '';
        }
        return date('M j, Y g:i A', strtotime($ts));
    }
