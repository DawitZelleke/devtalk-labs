<?php
/**
 * DevTalk API extension — Cross-Origin Resource Sharing (CORS) policy.
 *
 * Called once, at the top of public/api/index.php, before any route runs.
 *
 * Lab 8 Patch #A1. The previous version reflected ANY request Origin back in
 * Access-Control-Allow-Origin together with Access-Control-Allow-Credentials:
 * true, so every website a logged-in user visited could read their API data.
 *
 * DevTalk's own pages (including messages.php) are same-origin and need no
 * CORS. The only other origin allowed to read API responses is the planned
 * front end at http://localhost:5173.
 */

/** Exact origins (scheme://host:port) allowed to read API responses. */
const API_CORS_ALLOWED_ORIGINS = [
    'http://localhost:5173',
];

function api_cors_origin_allowed(string $origin): bool
{
    // Exact, strict comparison only. "null" (sandboxed iframes, file://,
    // some redirects) is never on the list, so it is never allowed.
    return $origin !== 'null' && in_array($origin, API_CORS_ALLOWED_ORIGINS, true);
}

function api_cors(): void
{
    // Responses differ by Origin, so caches must key on it.
    header('Vary: Origin');

    $origin  = $_SERVER['HTTP_ORIGIN'] ?? '';
    $allowed = is_string($origin) && api_cors_origin_allowed($origin);

    if ($allowed) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Credentials: true');
    }

    // CORS preflight (sent by the browser before a PATCH, a JSON POST, or any
    // request with an Authorization header). Only an allowed origin gets the
    // Access-Control-* answers; any other origin gets none, so the browser
    // blocks the real request.
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        if ($allowed) {
            header('Access-Control-Allow-Methods: GET, POST, PATCH, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization');
            header('Access-Control-Max-Age: 600');
        }
        http_response_code(204);
        exit;
    }
}
