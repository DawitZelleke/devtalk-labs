<?php
require_once __DIR__ . '/../src/helpers.php';
require_login();
require_post();
verify_csrf();

$id = $_POST['id'] ?? '';

$stmt = db()->prepare('SELECT * FROM topics WHERE id = ?');
$stmt->execute([$id]);
$topic = $stmt->fetch();

if (!$topic) {
    header('Location: index.php');
    exit;
}

// Authorization: the topic's owner may delete it; admins may moderate any topic.
if ((int) $topic['user_id'] !== current_user_id() && !current_user_is_admin()) {
    forbid('You can only delete your own topics.');
}

$del = db()->prepare('DELETE FROM topics WHERE id = ?');
$del->execute([$id]);

header('Location: index.php');
exit;
