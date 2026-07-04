<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_theme_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $theme = 'teal';

    mysqli_query($mysqli,"UPDATE settings SET config_theme = '$theme' WHERE company_id = 1");

    logAction("Settings", "Edit", "$session_name kept the N45 dark theme active");

    flash_alert("N45 dark theme is active");

    redirect();

}

if (isset($_POST['edit_favicon_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    // Check to see if a file is attached
    if (isset($_FILES['file']['tmp_name'])) {
        if ($new_file_name = checkFileUpload($_FILES['file'], array('ico'))) {
            $file_tmp_path = $_FILES['file']['tmp_name'];

            // Delete old file
            if(file_exists("../uploads/favicon.ico")) {
                unlink("../uploads/favicon.ico");
            }

            // directory in which the uploaded file will be moved
            $upload_file_dir = "../uploads/";
            //Force File Name
            $new_file_name = "favicon.ico";
            $dest_path = $upload_file_dir . $new_file_name;

            move_uploaded_file($file_tmp_path, $dest_path);
        }
    }

    logAction("Settings", "Edit", "$session_name changed the favicon");

    flash_alert("Favicon Updated");

    redirect();

}

if (isset($_POST['reset_favicon']) || isset($_GET['reset_favicon'])) {

    $csrf_token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    validateCSRFToken($csrf_token);

    if (file_exists("../uploads/favicon.ico")) {
        unlink("../uploads/favicon.ico");
    }

    logAction("Settings", "Edit", "$session_name reset Favicon");

    flash_alert("Favicon reset", 'error');

    redirect();

}
