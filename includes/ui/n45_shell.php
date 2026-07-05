<?php
require_once __DIR__ . '/n45_helpers.php';
require_once __DIR__ . '/n45_components.php';
require_once __DIR__ . '/n45_nav.php';

if (!function_exists('n45_render_topbar')) {
    function n45_render_topbar()
    {
        global $mysqli, $session_user_id, $session_avatar, $session_name, $session_user_role_display, $session_is_admin;

        $query = isset($_GET['query']) ? nullable_htmlentities($_GET['query']) : '';
        $area = n45_area_label();

        $customLinks = '';
        if (!empty($mysqli)) {
            $sql_custom_links = mysqli_query($mysqli, "SELECT * FROM custom_links WHERE custom_link_location = 2 AND custom_link_archived_at IS NULL ORDER BY custom_link_order ASC, custom_link_name ASC");

            while ($row = mysqli_fetch_assoc($sql_custom_links)) {
                $custom_link_name = nullable_htmlentities($row['custom_link_name']);
                $custom_link_uri = sanitize_url($row['custom_link_uri']);
                $custom_link_icon = nullable_htmlentities($row['custom_link_icon'] ?: 'external-link-alt');
                $target = intval($row['custom_link_new_tab']) === 1 ? " target='_blank' rel='noopener noreferrer'" : '';

                $customLinks .= '
                    <a href="' . $custom_link_uri . '"' . $target . ' class="n45-topbar-button" title="' . $custom_link_name . '">
                        <i class="fas fa-' . $custom_link_icon . '" aria-hidden="true"></i>
                    </a>
                ';
            }
        }

        $num_notifications = 0;
        if (!empty($mysqli) && !empty($session_user_id)) {
            $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT('notification_id') AS num FROM notifications WHERE notification_user_id = $session_user_id AND notification_dismissed_at IS NULL"));
            $num_notifications = intval($row['num']);
        }

        $avatar = '<i class="fas fa-user-circle" aria-hidden="true"></i>';
        if (!empty($session_avatar)) {
            $avatar = '<img src="/uploads/users/' . intval($session_user_id) . '/' . n45_attr($session_avatar) . '" alt="">';
        }

        return '
            <div class="n45-main">
                <header class="n45-topbar">
                    <div class="n45-topbar__left">
                        <button class="n45-topbar-button" type="button" data-n45-sidebar-toggle aria-label="Toggle navigation">
                            <i class="fas fa-bars" aria-hidden="true"></i>
                        </button>
                        <div class="n45-workspace-switcher">
                            <strong>N45 PSA</strong>
                            <span>' . n45_safe($area) . '</span>
                        </div>
                    </div>

                    <form class="n45-global-search" action="/agent/global_search.php" role="search">
                        <label class="sr-only" for="n45-global-search">Global Search</label>
                        <i class="fas fa-search" aria-hidden="true"></i>
                        <input id="n45-global-search" type="search" placeholder="Search clients, tickets, assets, credentials" name="query" value="' . $query . '">
                        <button type="submit">Search</button>
                    </form>

                    <div class="n45-topbar__actions">
                        ' . $customLinks . '
                        <a class="n45-topbar-button ajax-modal" href="#" data-modal-url="/modals/notifications.php" aria-label="Notifications">
                            <i class="fas fa-bell" aria-hidden="true"></i>
                            ' . ($num_notifications > 0 ? '<span class="n45-count">' . n45_safe($num_notifications) . '</span>' : '') . '
                        </a>

                        <div class="dropdown n45-user-menu">
                            <a href="#" class="n45-user-menu__toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <span class="n45-user-menu__avatar">' . $avatar . '</span>
                                <span class="n45-user-menu__copy">
                                    <strong>' . n45_safe(stripslashes($session_name ?? 'Account')) . '</strong>
                                    <small>' . n45_safe($session_user_role_display ?? '') . '</small>
                                </span>
                                <i class="fas fa-chevron-down" aria-hidden="true"></i>
                            </a>
                            <div class="dropdown-menu dropdown-menu-right n45-dropdown">
                                ' . (!empty($session_is_admin) ? '<a href="/admin" class="dropdown-item"><i class="fas fa-user-shield mr-2"></i>Administration</a>' : '') . '
                                <a href="/agent/user/user_details.php" class="dropdown-item"><i class="fas fa-user-cog mr-2"></i>Account</a>
                                <div class="dropdown-divider"></div>
                                <a href="/agent/post.php?logout" class="dropdown-item"><i class="fas fa-sign-out-alt mr-2"></i>Logout</a>
                            </div>
                        </div>
                    </div>
                </header>
        ';
    }
}
