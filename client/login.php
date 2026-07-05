<?php
/*
 * Client Portal
 * Customer login page
 */

header("Content-Security-Policy: default-src 'self'");

if (!file_exists('../config.php')) {
    header("Location: /setup");
    exit();
}

require_once '../config.php';
require_once '../includes/load_global_settings.php';
require_once '../functions.php';

if (!isset($config_enable_setup) || $config_enable_setup == 1) {
    header("Location: /setup");
    exit();
}

if ($config_client_portal_enable == 0) {
    echo "Client Portal is Disabled";
    exit();
}

if (!isset($_SESSION)) {
    ini_set("session.cookie_httponly", true);
    if ($config_https_only) {
        ini_set("session.cookie_secure", true);
    }
    session_start();
}

require_once '../includes/inc_set_timezone.php';

$session_ip = sanitizeInput(getIP());
$session_user_agent = sanitizeInput($_SERVER['HTTP_USER_AGENT'] ?? '');
$session_user_id = 0;
$response = null;
$email = '';

$company_sql = mysqli_query($mysqli, "SELECT company_name, company_logo FROM companies WHERE company_id = 1");
$company_row = mysqli_fetch_assoc($company_sql);
$company_name = $company_row['company_name'];
$company_logo = $company_row['company_logo'];

$azure_client_id = $config_azure_client_id ?? null;

if (isset($_SESSION['client_logged_in']) && $_SESSION['client_logged_in']) {
    header("Location: /client/index.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = sanitizeInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        header("HTTP/1.1 401 Unauthorized");
        $response = "<div class='alert alert-danger'>Incorrect username or password.</div>";
    } else {
        $sql = mysqli_query($mysqli, "
            SELECT users.user_id, users.user_email, users.user_password, users.user_auth_method,
                   contacts.contact_id, contacts.contact_client_id,
                   clients.client_id
            FROM users
            LEFT JOIN contacts ON users.user_id = contacts.contact_user_id
            LEFT JOIN clients ON contacts.contact_client_id = clients.client_id
            WHERE users.user_email = '$email'
              AND users.user_archived_at IS NULL
              AND users.user_status = 1
              AND users.user_type = 2
              AND users.user_auth_method = 'local'
              AND clients.client_archived_at IS NULL
            LIMIT 1
        ");
        $row = mysqli_fetch_assoc($sql);

        if (
            $row
            && password_verify($password, $row['user_password'])
            && intval($row['contact_client_id']) > 0
            && intval($row['contact_id']) > 0
        ) {
            $user_id = intval($row['user_id']);
            $client_id = intval($row['contact_client_id']);
            $contact_id = intval($row['contact_id']);
            $user_email = sanitizeInput($row['user_email']);

            $_SESSION['client_logged_in'] = true;
            $_SESSION['client_id'] = $client_id;
            $_SESSION['user_id'] = $user_id;
            $_SESSION['user_type'] = 2;
            $_SESSION['contact_id'] = $contact_id;
            $_SESSION['login_method'] = 'local';
            $_SESSION['logged'] = true;
            $_SESSION['csrf_token'] = randomString(32);

            $session_user_id = $user_id;
            logAction("Client Login", "Success", "Client contact $user_email successfully logged in locally", $client_id, $user_id);

            header("Location: /client/index.php");
            exit();
        }

        header("HTTP/1.1 401 Unauthorized");
        logAction("Client Login", "Failed", "Failed client portal login attempt using $email");
        $response = "<div class='alert alert-danger'>Incorrect username or password.</div>";
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title><?php echo nullable_htmlentities($company_name); ?> | Client Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex">
    <link rel="stylesheet" href="../plugins/fontawesome-free/css/all.min.css">
    <?php if(file_exists('../uploads/favicon.ico')) { ?>
        <link rel="icon" type="image/x-icon" href="/uploads/favicon.ico">
    <?php } ?>
    <link rel="stylesheet" href="../plugins/adminlte/css/adminlte.min.css">
    <link rel="stylesheet" href="../css/itflow_custom.css">
    <link rel="stylesheet" href="../css/n45_ui.css">
</head>
<body class="hold-transition login-page dark-mode n45-auth-page">

<div class="n45-auth-shell">
    <section class="n45-auth-side">
        <div>
            <div class="n45-auth-kicker">Client Portal</div>
            <h1><?php echo nullable_htmlentities($company_name); ?></h1>
            <p>Access tickets, invoices, quotes, documents, and service history for your organization.</p>
        </div>
        <div class="n45-auth-footer">
            <?php if (!$config_whitelabel_enabled) { ?>
                Powered by ITFlow
            <?php } ?>
        </div>
    </section>

    <section class="n45-auth-card-wrap">
        <div class="n45-auth-card">
            <div class="n45-auth-logo">
                <?php if (!empty($company_logo)) { ?>
                    <img alt="<?php echo nullable_htmlentities($company_name); ?> logo" src="<?php echo "/uploads/settings/$company_logo"; ?>">
                <?php } else { ?>
                    <span class="n45-brand-mark" aria-hidden="true"><span>N45</span></span>
                    <div>
                        <div class="n45-auth-title mb-0">Client Portal</div>
                        <div class="n45-auth-subtitle mb-0"><?php echo nullable_htmlentities($company_name); ?></div>
                    </div>
                <?php } ?>
            </div>

    <div class="card">
        <div class="card-body login-card-body">
            <p class="login-box-msg">Use your client portal credentials.</p>

            <?php if (isset($_SESSION['login_message'])) { ?>
                <div class="alert alert-info"><?php echo nullable_htmlentities($_SESSION['login_message']); ?></div>
                <?php unset($_SESSION['login_message']); ?>
            <?php } ?>

            <?php if (isset($response)) { ?>
                <?php echo $response; ?>
            <?php } ?>

            <form method="post">
                <div class="input-group mb-3">
                    <input type="email" class="form-control" placeholder="Email" name="email" value="<?php echo htmlspecialchars($email, ENT_QUOTES); ?>" required autofocus>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-envelope"></span>
                        </div>
                    </div>
                </div>

                <div class="input-group mb-3">
                    <input type="password" class="form-control" placeholder="Password" name="password" required>
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-lock"></span>
                        </div>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-block mb-3" name="login">Sign In</button>

                <?php if (!empty($azure_client_id)) { ?>
                    <a href="/client/login_microsoft.php" class="btn btn-secondary btn-block mb-3">
                        <i class="fas fa-building mr-2"></i>Login with Microsoft Entra
                    </a>
                <?php } ?>
            </form>

            <?php if (!empty($config_smtp_host)) { ?>
                <a href="/client/login_reset.php">Forgot password?</a>
            <?php } ?>
        </div>
    </div>

    <?php if (!$config_whitelabel_enabled) { ?>
        <p class="text-center mt-3"><small class="text-muted">Powered by ITFlow</small></p>
    <?php } ?>
</div>

<script src="../plugins/jquery/jquery.min.js"></script>
<script src="../plugins/bootstrap/js/bootstrap.bundle.min.js"></script>
<script src="../plugins/adminlte/js/adminlte.min.js"></script>
<script src="../js/login_prevent_resubmit.js"></script>

</body>
</html>
