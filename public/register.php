<?php
require_once __DIR__ . '/../src/helpers.php';

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $username = trim($_POST['username'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $email === '' || $password === '') {
        $error = 'All fields are required.';
    } else {
        try {
            $stmt = db()->prepare(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)'
            );
            $stmt->execute([$username, $email, password_hash($password, PASSWORD_DEFAULT)]);
            login_user((int) db()->lastInsertId());
            header('Location: index.php');
            exit;
        } catch (PDOException $e) {
            log_exception($e, 'register');
            $error = 'Could not create the account. Please try a different username.';
        }
    }
}

render_header('Register');
?>
<div class="row justify-content-center">
    <div class="col-md-5">
        <h1 class="h4 mb-3">Create an account</h1>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <form method="post" class="card card-body shadow-sm">
            <?= csrf_field() ?>
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input name="username" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Email</label>
                <input name="email" type="email" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input name="password" type="password" class="form-control" required>
            </div>
            <button class="btn btn-primary">Register</button>
            <p class="small mt-3 mb-0">Already have an account? <a href="login.php">Log in</a>.</p>
        </form>
    </div>
</div>
<?php render_footer(); ?>