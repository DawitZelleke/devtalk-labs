<?php
require_once __DIR__ . '/errors.php'; // no public diagnostics; logs + 400/500 boundary

define('DB_PATH', __DIR__ . '/../database/forum.sqlite');
define('UPLOAD_DIR', __DIR__ . '/../public/uploads');
define('APP_NAME', 'DevTalk Forum');
