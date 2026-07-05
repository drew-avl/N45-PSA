<?php
require_once __DIR__ . '/n45_helpers.php';

if (!function_exists('n45_page_header')) {
    function n45_page_header($title = null, $subtitle = null, $actions = '')
    {
        global $page_title, $client_name;

        if (defined('N45_HIDE_PAGE_HEADER') && N45_HIDE_PAGE_HEADER) {
            return '';
        }

        $area = n45_current_area();
        $title = $title ?: ($page_title ?? n45_area_label($area));

        if (n45_current_file() === 'dashboard.php') {
            $title = 'Operations Dashboard';
            $subtitle = $subtitle ?: 'Financial and service desk signals for the selected operating year.';
        }

        if ($area === 'client-workspace' && !empty($client_name)) {
            $title = $client_name;
        }

        $subtitle = $subtitle ?: n45_page_subtitle($area);
        $section = n45_area_label($area);

        return '
            <section class="n45-page-header">
                <div class="n45-page-header__copy">
                    <div class="n45-eyebrow">' . n45_safe($section) . '</div>
                    <h1>' . n45_safe($title) . '</h1>
                    <p>' . n45_safe($subtitle) . '</p>
                </div>
                ' . $actions . '
            </section>
        ';
    }
}

if (!function_exists('n45_section_header')) {
    function n45_section_header($title, $subtitle = '', $actions = '')
    {
        return '
            <div class="n45-section-header">
                <div>
                    <h2>' . n45_safe($title) . '</h2>
                    ' . ($subtitle !== '' ? '<p>' . n45_safe($subtitle) . '</p>' : '') . '
                </div>
                ' . $actions . '
            </div>
        ';
    }
}

if (!function_exists('n45_panel_start')) {
    function n45_panel_start($title = '', $icon = '', $actions = '', $classes = '')
    {
        $heading = '';

        if ($title !== '' || $actions !== '') {
            $heading = '
                <div class="n45-panel__header">
                    <div class="n45-panel__title">
                        ' . ($icon !== '' ? n45_icon($icon) : '') . '
                        ' . ($title !== '' ? '<h3>' . n45_safe($title) . '</h3>' : '') . '
                    </div>
                    ' . $actions . '
                </div>
            ';
        }

        return '<section class="n45-panel ' . n45_attr($classes) . '">' . $heading . '<div class="n45-panel__body">';
    }
}

if (!function_exists('n45_panel_end')) {
    function n45_panel_end()
    {
        return '</div></section>';
    }
}

if (!function_exists('n45_metric_card')) {
    function n45_metric_card($label, $value, $href = '', $icon = 'circle', $meta = '', $tone = 'default')
    {
        $tag = $href !== '' ? 'a' : 'div';
        $hrefAttr = $href !== '' ? ' href="' . n45_attr($href) . '"' : '';

        return '
            <' . $tag . ' class="n45-metric-card n45-metric-card--' . n45_attr($tone) . '"' . $hrefAttr . '>
                <div class="n45-metric-card__copy">
                    <span>' . n45_safe($label) . '</span>
                    <strong>' . n45_safe($value) . '</strong>
                    ' . ($meta !== '' ? '<small>' . n45_safe($meta) . '</small>' : '') . '
                </div>
                <div class="n45-metric-card__icon">' . n45_icon($icon) . '</div>
            </' . $tag . '>
        ';
    }
}

if (!function_exists('n45_table_wrap_start')) {
    function n45_table_wrap_start($classes = '')
    {
        return '<div class="n45-table-wrap ' . n45_attr($classes) . '">';
    }
}

if (!function_exists('n45_table_wrap_end')) {
    function n45_table_wrap_end()
    {
        return '</div>';
    }
}

if (!function_exists('n45_empty_state')) {
    function n45_empty_state($title, $message = '', $icon = 'inbox')
    {
        return '
            <div class="n45-empty-state">
                <div class="n45-empty-state__icon">' . n45_icon($icon) . '</div>
                <h3>' . n45_safe($title) . '</h3>
                ' . ($message !== '' ? '<p>' . n45_safe($message) . '</p>' : '') . '
            </div>
        ';
    }
}

if (!function_exists('n45_status_badge')) {
    function n45_status_badge($label, $tone = 'neutral', $style = '')
    {
        $styleAttr = $style !== '' ? ' style="' . n45_attr($style) . '"' : '';

        return '<span class="n45-status n45-status--' . n45_attr($tone) . '"' . $styleAttr . '>' . n45_safe($label) . '</span>';
    }
}

if (!function_exists('n45_action_toolbar_start')) {
    function n45_action_toolbar_start($classes = '')
    {
        return '<div class="n45-action-toolbar ' . n45_attr($classes) . '">';
    }
}

if (!function_exists('n45_action_toolbar_end')) {
    function n45_action_toolbar_end()
    {
        return '</div>';
    }
}

if (!function_exists('n45_form_section_start')) {
    function n45_form_section_start($title = '', $subtitle = '')
    {
        return '
            <section class="n45-form-section">
                ' . ($title !== '' ? '<div class="n45-form-section__header"><h3>' . n45_safe($title) . '</h3>' . ($subtitle !== '' ? '<p>' . n45_safe($subtitle) . '</p>' : '') . '</div>' : '') . '
        ';
    }
}

if (!function_exists('n45_form_section_end')) {
    function n45_form_section_end()
    {
        return '</section>';
    }
}

if (!function_exists('n45_client_context_header')) {
    function n45_client_context_header()
    {
        global $client_name, $client_abbreviation, $client_tags_display;

        if (empty($client_name)) {
            return '';
        }

        return '
            <section class="n45-client-context">
                <div class="n45-client-context__mark">' . n45_safe($client_abbreviation ?: substr($client_name, 0, 2)) . '</div>
                <div>
                    <div class="n45-eyebrow">Client Workspace</div>
                    <h2>' . n45_safe($client_name) . '</h2>
                    <div class="n45-client-context__tags">' . ($client_tags_display ?? '') . '</div>
                </div>
            </section>
        ';
    }
}
