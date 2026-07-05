<!-- Main Sidebar Container -->
<aside class="main-sidebar sidebar-dark-teal d-print-none n45-sidebar">

    <a class="brand-link n45-brand-link" href="/agent/<?php echo $config_start_page ?>">
        <?php echo n45_brand_mark(); ?>
        <span class="brand-text n45-brand-copy">
            <strong>Account</strong>
            <small><i class="fas fa-arrow-left mr-1"></i>Back to workspace</small>
        </span>
    </a>

    <!-- Sidebar -->
    <div class="sidebar">

        <!-- Sidebar Menu -->
        <nav>

            <ul class="nav nav-pills nav-sidebar flex-column mt-2" data-widget="treeview" role="menu" data-accordion="false">

                <li class="nav-item">
                    <a href="/agent/user/user_details.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "user_details.php") { echo "active"; } ?>">
                        <i class="nav-icon fas fa-user"></i>
                        <p>Details</p>
                    </a>
                </li>

               <li class="nav-item mt-2">
                    <a href="/agent/user/user_security.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "user_security.php") { echo "active"; } ?>">
                        <i class="nav-icon fas fa-shield-alt"></i>
                        <p>Security</p>
                    </a>
                </li>

                <li class="nav-item mt-2">
                    <a href="/agent/user/user_preferences.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "user_preferences.php") { echo "active"; } ?>">
                        <i class="nav-icon fas fa-cogs"></i>
                        <p>Preferences</p>
                    </a>
                </li>

                <li class="nav-item mt-2">
                    <a href="/agent/user/user_activity.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "user_activity.php") { echo "active"; } ?>">
                        <i class="nav-icon fas fa-clock"></i>
                        <p>Activity</p>
                    </a>
                </li>

            </ul>
        </nav>
        <!-- /.sidebar-menu -->

        <div class="mb-3"></div>

    </div>
    <!-- /.sidebar -->
</aside>
