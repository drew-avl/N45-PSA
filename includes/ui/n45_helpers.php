<?php
/*
 * N45 UI helpers.
 *
 * Presentation-only helpers for the custom N45 shell. These functions avoid
 * auth, routing, database mutation, CSRF, and form handling behavior.
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

if (!function_exists('n45_attr')) {
    function n45_attr($value)
    {
        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('n45_current_path')) {
    function n45_current_path()
    {
        return parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    }
}

if (!function_exists('n45_current_file')) {
    function n45_current_file()
    {
        return basename(parse_url($_SERVER['PHP_SELF'] ?? n45_current_path(), PHP_URL_PATH) ?: '');
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
            return 'Client workspace, service history, billing, documentation, and assets.';
        }

        $subtitles = [
            'admin' => 'Platform controls, access, integrations, automation, and system operations.',
            'account' => 'Personal profile, security, preferences, and activity.',
            'client-portal' => 'Service access for your organization.',
            'guest' => 'Secure shared access.',
            'reports' => 'Operational reporting and decision support.',
            'operations' => 'Service desk, clients, assets, billing, field work, and delivery operations.',
        ];

        return $subtitles[$area] ?? ($session_company_name ?? 'N45 PSA');
    }
}

if (!function_exists('n45_body_classes')) {
    function n45_body_classes()
    {
        $area = n45_current_area();

        return 'n45-app n45-app--' . n45_attr($area);
    }
}

if (!function_exists('n45_brand_mark')) {
    function n45_brand_mark($label = 'N45')
    {
        return '<span class="n45-brand-mark" aria-hidden="true"><span>' . n45_safe($label) . '</span></span>';
    }
}

if (!function_exists('n45_is_active_path')) {
    function n45_is_active_path($matches)
    {
        $matches = is_array($matches) ? $matches : [$matches];
        $currentPath = n45_current_path();
        $currentFile = n45_current_file();

        foreach ($matches as $match) {
            if (!$match) {
                continue;
            }

            $matchPath = parse_url((string) $match, PHP_URL_PATH) ?: (string) $match;

            if ($matchPath === $currentPath || basename($matchPath) === $currentFile) {
                return true;
            }
        }

        return false;
    }
}

if (!function_exists('n45_icon')) {
    function n45_icon($icon, $classes = '')
    {
        $icon = $icon ?: 'circle';
        $classes = trim('fas fa-' . $icon . ' ' . $classes);

        return '<i class="' . n45_attr($classes) . '" aria-hidden="true"></i>';
    }
}

if (!function_exists('n45_has_permission')) {
    function n45_has_permission($permission, $minimum = 1)
    {
        if (!function_exists('lookupUserPermission')) {
            return false;
        }

        return lookupUserPermission($permission) >= $minimum;
    }
}

if (!function_exists('n45_file_exists_public')) {
    function n45_file_exists_public($path)
    {
        $path = '/' . ltrim((string) $path, '/');
        return file_exists($_SERVER['DOCUMENT_ROOT'] . $path);
    }
}
