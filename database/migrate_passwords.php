<?php

/**
 * One-time migration: hash any plaintext passwords left in an existing
 * database, then VACUUM so the old plaintext values are not left behind in
 * free database pages.
 *
 * Usage: php database/migrate_passwords.php
 */

require_once __DIR__ . '/../src/config.php';

$pdo = new PDO('sqlite:' . DB_PATH);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

$rows = $pdo->query('SELECT id, password FROM users')->fetchAll();
$upd  = $pdo->prepare('UPDATE users SET password = ? WHERE id = ?');

$migrated = 0;
$pdo->beginTransaction();
foreach ($rows as $r) {
    if (empty(password_get_info($r['password'])['algo'])) {
        $upd->execute([password_hash($r['password'], PASSWORD_DEFAULT), $r['id']]);
        $migrated++;
    }
}
$pdo->commit();
$pdo->exec('VACUUM');

echo "Hashed {$migrated} plaintext password(s); database vacuumed.\n";
