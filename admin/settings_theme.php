<?php
require_once "includes/inc_all_admin.php";

?>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-paint-brush mr-2"></i>Theme</h3>
    </div>
    <div class="card-body">
        <div class="n45-theme-lock d-flex align-items-center justify-content-between">
            <span><i class="fas fa-moon mr-2"></i>N45 Dark</span>
            <span class="badge badge-primary">Active</span>
        </div>
    </div>
</div>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-image mr-2"></i>Favicon</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" enctype="multipart/form-data" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <img class="mb-3" src="<?php if(file_exists("../uploads/favicon.ico")) { echo "../uploads/favicon.ico"; } else { echo "../favicon.ico"; } ?>">

            <div class="form-group">
                <input type="file" class="form-control-file" name="file" accept=".ico">
            </div>

            <hr>

            <button type="submit" name="edit_favicon_settings" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Upload Icon</button>
            <?php if(file_exists("../uploads/favicon.ico")) { ?>
            <form method="post" action="post.php" class="d-inline m-0">
                <input type="hidden" name="reset_favicon" value="1">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <button type="submit" class="btn btn-outline-danger"><i class="fas fa-redo-alt mr-2"></i>Reset Favicon</button>
            </form>
            <?php } ?>
        </form>
    </div>
</div>

<?php
require_once "../includes/footer.php";
