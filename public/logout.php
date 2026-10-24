<?php
require_once __DIR__ . '/../src/helpers.php';
require_post();
verify_csrf();
$_SESSION = [];
session_destroy();
header('Location: index.php');
exit;
