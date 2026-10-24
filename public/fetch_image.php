<?php
require_once __DIR__ . '/../src/config.php';

/*
 * Image preview endpoint.
 *
 * The server never fetches a user-supplied URL (that was the SSRF / local file
 * read in Lab 4). Instead:
 *   1. A scheme-less relative path is served only if it resolves to a bundled
 *      image under public/assets or public/uploads.
 *   2. An https URL on an approved image host is handed back to the browser as
 *      a redirect, so the browser fetches it directly.
 *   3. Everything else (file://, http://, loopback, any other host) is rejected.
 */

const APPROVED_IMAGE_HOSTS = [
    'images.unsplash.com',
    'i.imgur.com',
    'upload.wikimedia.org',
    'raw.githubusercontent.com',
];

$url = $_GET['url'] ?? '';
if ($url === '') {
    http_response_code(400);
    echo 'No url provided.';
    exit;
}

// --- Case 1: relative path -> serve a bundled image -----------------------
$hasScheme = (bool) preg_match('#^[a-z][a-z0-9+.\-]*:#i', $url);
$protocolRelative = strncmp($url, '//', 2) === 0;

if (!$hasScheme && !$protocolRelative) {
    $publicDir = realpath(__DIR__);
    $rel    = ltrim((string) parse_url($url, PHP_URL_PATH), '/');
    $target = realpath($publicDir . DIRECTORY_SEPARATOR . $rel);

    $allowedRoots = array_filter([
        realpath($publicDir . '/assets'),
        realpath($publicDir . '/uploads'),
    ]);

    $inside = false;
    if ($target && is_file($target)) {
        foreach ($allowedRoots as $root) {
            if (strncmp($target, $root . DIRECTORY_SEPARATOR, strlen($root) + 1) === 0) {
                $inside = true;
                break;
            }
        }
    }

    if (!$inside) {
        http_response_code(400);
        echo 'Invalid image path.';
        exit;
    }

    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($target) ?: 'application/octet-stream';
    if (strncmp($mime, 'image/', 6) !== 0) {
        http_response_code(400);
        echo 'Not an image.';
        exit;
    }

    header('Content-Type: ' . $mime);
    header('X-Content-Type-Options: nosniff');
    readfile($target);
    exit;
}

// --- Case 2: approved external https host -> browser redirect -------------
$parts = parse_url($url);
if (($parts['scheme'] ?? '') === 'https'
    && in_array(strtolower($parts['host'] ?? ''), APPROVED_IMAGE_HOSTS, true)) {
    header('Location: ' . $url, true, 302);
    exit;
}

// --- Case 3: everything else is rejected ----------------------------------
http_response_code(400);
echo 'Image URL not allowed.';
