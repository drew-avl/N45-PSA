<?php
/*
 * N45 UI helpers.
 *
 * These helpers only render presentation chrome. They intentionally avoid
 * route, auth, permission, form, CSRF, and database behavior.
 */

if (!function_exists('n45_safe')) {
    function n45_safe($value)
    {
        if ($value === null) {
            return '';
        }

        if (function_exists('nullable_htmlentities')) {
            return nullable_htmlentities((string) $value);
        }

        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('n45_current_path')) {
    function n45_current_path()
    {
        return parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    }
}

if (!function_exists('n45_current_area')) {
    function n45_current_area()
    {
        $path = n45_current_path();

        if (strpos($path, '/admin') === 0) {
            return 'admin';
        }

        if (strpos($path, '/client') === 0) {
            return 'client-portal';
        }

        if (strpos($path, '/guest') === 0) {
            return 'guest';
        }

        if (strpos($path, '/agent/user') === 0) {
            return 'account';
        }

        if (isset($_GET['client_id'])) {
            return 'client-workspace';
        }

        if (strpos($path, '/agent/reports') === 0) {
            return 'reports';
        }

        return 'operations';
    }
}

if (!function_exists('n45_area_label')) {
    function n45_area_label($area = null)
    {
        $area = $area ?: n45_current_area();

        $labels = [
            'admin' => 'Administration',
            'account' => 'Account',
            'client-portal' => 'Client Portal',
            'client-workspace' => 'Client Workspace',
            'guest' => 'Guest Access',
            'reports' => 'Reports',
            'operations' => 'Operations',
        ];

        return $labels[$area] ?? 'Workspace';
    }
}

if (!function_exists('n45_page_subtitle')) {
    function n45_page_subtitle($area = null)
    {
        global $client_name, $session_company_name;

        $area = $area ?: n45_current_area();

        if ($area === 'client-workspace' && !empty($client_name)) {
            return 'Operational workspace for ' . $client_name;
        }

        $subtitles = [
            'admin' => 'System controls, access, integrations, and platform configuration.',
            'account' => 'Personal settings, security, and activity.',
            'client-portal' => 'Service access for your organization.',
            'guest' => 'Secure shared access.',
            'reports' => 'Operational reporting and decision support.',
            'operations' => 'Tickets, clients, assets, credentials, billing, and field work.',
        ];

        return $subtitles[$area] ?? ($session_company_name ?? 'N45 PSA');
    }
}

if (!function_exists('n45_body_classes')) {
    function n45_body_classes()
    {
        $area = n45_current_area();

        return 'hold-transition sidebar-mini layout-fixed layout-navbar-fixed dark-mode n45-app n45-app--' . $area;
    }
}

if (!function_exists('n45_brand_mark')) {
    function n45_brand_mark($label = 'N45')
    {
        return '<span class="n45-brand-mark" aria-hidden="true"><span>' . n45_safe($label) . '</span></span>';
    }
}

if (!function_exists('n45_page_header')) {
    function n45_page_header($title = null, $subtitle = null)
    {
        global $page_title, $client_name;

        if (defined('N45_HIDE_PAGE_HEADER') && N45_HIDE_PAGE_HEADER) {
            return '';
        }

        $area = n45_current_area();
        $title = $title ?: ($page_title ?? n45_area_label($area));

        if ($area === 'client-workspace' && !empty($client_name)) {
            $title = $client_name;
        }

        $subtitle = $subtitle ?: n45_page_subtitle($area);
        $section = n45_area_label($area);

        return '
            <section class="n45-page-hero">
                <div class="n45-page-hero__copy">
                    <div class="n45-eyebrow">' . n45_safe($section) . '</div>
                    <h1>' . n45_safe($title) . '</h1>
                    <p>' . n45_safe($subtitle) . '</p>
                </div>
            </section>
        ';
    }
}
