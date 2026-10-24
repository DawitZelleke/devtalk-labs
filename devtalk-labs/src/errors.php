<?php

/*
 * Error handling and request-input boundary (Lab 5 Patch #9).
 *
 * - PHP diagnostics are never sent to the browser; they go to logs/php-error.log.
 * - Any uncaught exception becomes a generic 500 page (details logged).
 * - request_string() rejects array-shaped or oversized parameters with 400.
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
ini_set('html_errors', '0');

$logDir = __DIR__ . '/../logs';
if (!is_dir($logDir)) {
    @mkdir($logDir, 0775, true);
}
ini_set('error_log', $logDir . '/php-error.log');

set_exception_handler(function (Throwable $e): void {
    error_log(sprintf('[DevTalk] uncaught %s: %s in %s:%d',
        get_class($e), $e->getMessage(), $e->getFile(), $e->getLine()));
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/html; charset=utf-8');
    }
    echo '<!doctype html><meta charset="utf-8"><title>Error</title>'
        . '<p>Something went wrong. Please try again later.</p>';
});

/** Stop with a generic 400 response. */
function bad_request(string $msg = 'Invalid request parameter.'): void
{
    http_response_code(400);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>Bad request</title><p>'
        . htmlspecialchars($msg) . '</p>';
    exit;
}

/**
 * Read a scalar string parameter from $source ($_GET / $_POST).
 * Missing -> $default. Array-shaped or longer than $maxLen -> 400.
 */
function request_string(array $source, string $key, int $maxLen = 255, string $default = ''): string
{
    if (!array_key_exists($key, $source)) {
        return $default;
    }
    $v = $source[$key];
    if (!is_string($v) || strlen($v) > $maxLen) {
        bad_request();
    }
    return $v;
}
