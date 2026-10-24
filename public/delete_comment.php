<?php
require_once __DIR__ . '/../src/helpers.php';
require_login();

$id      = $_GET['id'] ?? '';
$topicId = $_GET['topic_id'] ?? '';

$stmt = db()->prepare('SELECT * FROM comments WHERE id = ?');
$stmt->execute([$id]);
$comment = $stmt->fetch();

if (!$comment) {
    header('Location: topic.php?id=' . (int) $topicId);
    exit;
}

// Authorization: the comment's author may delete it; admins may moderate any comment.
if ((int) $comment['user_id'] !== current_user_id() && !current_user_is_admin()) {
    forbid('You can only delete your own comments.');
}

$del = db()->prepare('DELETE FROM comments WHERE id = ?');
$del->execute([$id]);

header('Location: topic.php?id=' . (int) $topicId);
exit;
