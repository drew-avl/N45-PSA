<?php
require_once __DIR__ . '/n45_helpers.php';

if (!function_exists('n45_nav_item')) {
    function n45_nav_item($item)
    {
        if (isset($item['visible']) && !$item['visible']) {
            return '';
        }

        $label = $item['label'] ?? '';
        $url = $item['url'] ?? '#';
        $icon = $item['icon'] ?? 'circle';
        $activeMatches = $item['active'] ?? $url;
        $active = n45_is_active_path($activeMatches);
        $target = !empty($item['target']) ? ' target="' . n45_attr($item['target']) . '" rel="noopener noreferrer"' : '';
        $badge = '';

        if (isset($item['badge']) && $item['badge'] !== '' && intval($item['badge']) > 0) {
            $badge = '<span class="n45-nav-badge">' . n45_safe($item['badge']) . '</span>';
        }

        if (!empty($item['disabled'])) {
            return '
                <li class="n45-nav-item n45-nav-item--disabled">
                    <span class="n45-nav-link">' . n45_icon($icon) . '<span>' . n45_safe($label) . '</span></span>
                </li>
            ';
        }

        return '
            <li class="n45-nav-item">
                <a class="n45-nav-link' . ($active ? ' is-active' : '') . '" href="' . n45_attr($url) . '"' . $target . '>
                    ' . n45_icon($icon) . '
                    <span>' . n45_safe($label) . '</span>
                    ' . $badge . '
                </a>
            </li>
        ';
    }
}

if (!function_exists('n45_nav_group')) {
    function n45_nav_group($title, $items)
    {
        $html = '';

        foreach ($items as $item) {
            $html .= n45_nav_item($item);
        }

        if (trim($html) === '') {
            return '';
        }

        return '
            <section class="n45-nav-group">
                <h2>' . n45_safe($title) . '</h2>
                <ul>' . $html . '</ul>
            </section>
        ';
    }
}

if (!function_exists('n45_sidebar')) {
    function n45_sidebar($title, $subtitle, $href, $groups, $footer = '')
    {
        $groupHtml = '';

        foreach ($groups as $group) {
            $groupHtml .= n45_nav_group($group['title'], $group['items']);
        }

        return '
            <aside class="n45-sidebar d-print-none" id="n45-sidebar">
                <a class="n45-sidebar-brand" href="' . n45_attr($href) . '">
                    ' . n45_brand_mark() . '
                    <span>
                        <strong>' . n45_safe($title) . '</strong>
                        <small>' . n45_safe($subtitle) . '</small>
                    </span>
                </a>
                <nav class="n45-sidebar-nav" aria-label="Primary navigation">
                    ' . $groupHtml . '
                </nav>
                <div class="n45-sidebar-footer">' . $footer . '</div>
            </aside>
        ';
    }
}

if (!function_exists('n45_custom_nav_items')) {
    function n45_custom_nav_items($location)
    {
        global $mysqli;

        if (empty($mysqli)) {
            return [];
        }

        $items = [];
        $location = intval($location);
        $sql = mysqli_query($mysqli, "SELECT * FROM custom_links WHERE custom_link_location = $location AND custom_link_archived_at IS NULL ORDER BY custom_link_order ASC, custom_link_name ASC");

        while ($row = mysqli_fetch_assoc($sql)) {
            $items[] = [
                'label' => $row['custom_link_name'],
                'url' => sanitize_url($row['custom_link_uri']),
                'icon' => $row['custom_link_icon'] ?: 'external-link-alt',
                'target' => intval($row['custom_link_new_tab']) === 1 ? '_blank' : '',
            ];
        }

        return $items;
    }
}

if (!function_exists('n45_render_agent_sidebar')) {
    function n45_render_agent_sidebar()
    {
        global $session_company_name, $session_is_admin, $config_module_enable_ticketing, $config_module_enable_accounting,
            $config_module_enable_itdoc, $num_active_clients, $num_active_tickets, $num_recurring_tickets,
            $num_active_projects, $num_open_quotes, $num_open_invoices, $num_recurring_invoices,
            $num_recurring_expenses;

        $groups = [
            [
                'title' => 'Command',
                'items' => [
                    ['label' => 'Dashboard', 'url' => '/agent/dashboard.php', 'icon' => 'tachometer-alt', 'active' => ['dashboard.php']],
                    ['label' => 'Global Search', 'url' => '/agent/global_search.php', 'icon' => 'search', 'active' => ['global_search.php']],
                    ['label' => 'Calendar', 'url' => '/agent/calendar.php', 'icon' => 'calendar-alt', 'active' => ['calendar.php']],
                ],
            ],
            [
                'title' => 'Service Desk',
                'items' => [
                    ['label' => 'Tickets', 'url' => '/agent/tickets.php', 'icon' => 'life-ring', 'badge' => $num_active_tickets ?? 0, 'active' => ['tickets.php', 'ticket.php'], 'visible' => $config_module_enable_ticketing == 1 && n45_has_permission('module_support')],
                    ['label' => 'Recurring Tickets', 'url' => '/agent/recurring_tickets.php', 'icon' => 'redo-alt', 'badge' => $num_recurring_tickets ?? 0, 'active' => ['recurring_tickets.php'], 'visible' => $config_module_enable_ticketing == 1 && n45_has_permission('module_support')],
                    ['label' => 'Projects', 'url' => '/agent/projects.php', 'icon' => 'project-diagram', 'badge' => $num_active_projects ?? 0, 'active' => ['projects.php', 'project_details.php'], 'visible' => $config_module_enable_ticketing == 1 && n45_has_permission('module_support')],
                ],
            ],
            [
                'title' => 'Organizations',
                'items' => [
                    ['label' => 'Clients', 'url' => '/agent/clients.php', 'icon' => 'users', 'badge' => $num_active_clients ?? 0, 'active' => ['clients.php', 'client_overview.php'], 'visible' => n45_has_permission('module_client')],
                    ['label' => 'Contacts', 'url' => '/agent/contacts.php', 'icon' => 'address-book', 'active' => ['contacts.php', 'contact_details.php'], 'visible' => n45_has_permission('module_client')],
                    ['label' => 'Locations', 'url' => '/agent/locations.php', 'icon' => 'map-marker-alt', 'active' => ['locations.php'], 'visible' => n45_has_permission('module_client')],
                    ['label' => 'Assets', 'url' => '/agent/assets.php', 'icon' => 'desktop', 'active' => ['assets.php', 'asset_details.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_support')],
                    ['label' => 'Vendors', 'url' => '/agent/vendors.php', 'icon' => 'building', 'active' => ['vendors.php', 'vendor_details.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                ],
            ],
            [
                'title' => 'Revenue',
                'items' => [
                    ['label' => 'Quotes', 'url' => '/agent/quotes.php', 'icon' => 'comment-dollar', 'badge' => $num_open_quotes ?? 0, 'active' => ['quotes.php', 'quote.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_sales')],
                    ['label' => 'Invoices', 'url' => '/agent/invoices.php', 'icon' => 'file-invoice', 'badge' => $num_open_invoices ?? 0, 'active' => ['invoices.php', 'invoice.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_sales')],
                    ['label' => 'Recurring Invoices', 'url' => '/agent/recurring_invoices.php', 'icon' => 'redo-alt', 'badge' => $num_recurring_invoices ?? 0, 'active' => ['recurring_invoices.php', 'recurring_invoice.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_sales')],
                    ['label' => 'Products', 'url' => '/agent/products.php', 'icon' => 'box-open', 'active' => ['products.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_sales')],
                    ['label' => 'Payments', 'url' => '/agent/payments.php', 'icon' => 'credit-card', 'active' => ['payments.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                ],
            ],
            [
                'title' => 'Operations',
                'items' => [
                    ['label' => 'Trips', 'url' => '/agent/trips.php', 'icon' => 'route', 'active' => ['trips.php'], 'visible' => $config_module_enable_accounting == 1],
                    ['label' => 'Expenses', 'url' => '/agent/expenses.php', 'icon' => 'shopping-cart', 'active' => ['expenses.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Recurring Expenses', 'url' => '/agent/recurring_expenses.php', 'icon' => 'clock', 'badge' => $num_recurring_expenses ?? 0, 'active' => ['recurring_expenses.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Accounts', 'url' => '/agent/accounts.php', 'icon' => 'piggy-bank', 'active' => ['accounts.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Transfers', 'url' => '/agent/transfers.php', 'icon' => 'exchange-alt', 'active' => ['transfers.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                ],
            ],
            [
                'title' => 'Intelligence',
                'items' => [
                    ['label' => 'Reports', 'url' => '/agent/reports/', 'icon' => 'chart-line', 'active' => ['/agent/reports/', 'income_summary.php', 'ticket_summary.php'], 'visible' => n45_has_permission('module_reporting')],
                ],
            ],
            [
                'title' => 'Admin',
                'items' => [
                    ['label' => 'Administration', 'url' => '/admin/', 'icon' => 'user-shield', 'active' => ['/admin/'], 'visible' => !empty($session_is_admin)],
                ],
            ],
        ];

        $custom = n45_custom_nav_items(1);
        if (!empty($custom)) {
            $groups[] = ['title' => 'Custom', 'items' => $custom];
        }

        $footer = '<a href="/agent/user/user_details.php">' . n45_icon('user-cog') . '<span>Account settings</span></a>';

        return n45_sidebar('N45 PSA', $session_company_name ?? 'Operations', '/agent/dashboard.php', $groups, $footer);
    }
}

if (!function_exists('n45_render_client_workspace_sidebar')) {
    function n45_render_client_workspace_sidebar()
    {
        global $client_id, $client_abbreviation, $config_module_enable_ticketing, $config_module_enable_itdoc,
            $config_module_enable_accounting, $num_contacts, $num_locations, $num_assets, $num_active_tickets,
            $num_recurring_tickets, $num_active_projects, $num_vendors, $num_calendar_events, $num_software,
            $num_credentials, $num_networks, $num_racks, $num_certificates, $num_domains, $num_services,
            $num_files, $num_invoices, $num_invoices_open, $num_recurring_invoices, $num_quotes, $num_payments,
            $num_trips, $num_software_expiring, $num_software_expired, $num_certificates_expiring,
            $num_certificates_expired, $num_domains_expiring_warning, $num_domains_urgent;

        $clientQuery = '?client_id=' . intval($client_id);

        $groups = [
            [
                'title' => 'Workspace',
                'items' => [
                    ['label' => 'Overview', 'url' => '/agent/client_overview.php' . $clientQuery, 'icon' => 'tachometer-alt', 'active' => ['client_overview.php']],
                    ['label' => 'Contacts', 'url' => '/agent/contacts.php' . $clientQuery, 'icon' => 'address-book', 'badge' => $num_contacts ?? 0, 'active' => ['contacts.php', 'contact_details.php']],
                    ['label' => 'Locations', 'url' => '/agent/locations.php' . $clientQuery, 'icon' => 'map-marker-alt', 'badge' => $num_locations ?? 0, 'active' => ['locations.php']],
                    ['label' => 'Vendors', 'url' => '/agent/vendors.php' . $clientQuery, 'icon' => 'building', 'badge' => $num_vendors ?? 0, 'active' => ['vendors.php', 'vendor_details.php']],
                    ['label' => 'Calendar', 'url' => '/agent/calendar.php' . $clientQuery, 'icon' => 'calendar-alt', 'badge' => $num_calendar_events ?? 0, 'active' => ['calendar.php']],
                ],
            ],
            [
                'title' => 'Service Desk',
                'items' => [
                    ['label' => 'Tickets', 'url' => '/agent/tickets.php' . $clientQuery, 'icon' => 'life-ring', 'badge' => $num_active_tickets ?? 0, 'active' => ['tickets.php', 'ticket.php'], 'visible' => $config_module_enable_ticketing == 1 && n45_has_permission('module_support')],
                    ['label' => 'Recurring Tickets', 'url' => '/agent/recurring_tickets.php' . $clientQuery, 'icon' => 'redo-alt', 'badge' => $num_recurring_tickets ?? 0, 'active' => ['recurring_tickets.php'], 'visible' => $config_module_enable_ticketing == 1 && n45_has_permission('module_support')],
                    ['label' => 'Projects', 'url' => '/agent/projects.php' . $clientQuery, 'icon' => 'project-diagram', 'badge' => $num_active_projects ?? 0, 'active' => ['projects.php', 'project_details.php'], 'visible' => $config_module_enable_ticketing == 1 && n45_has_permission('module_support')],
                ],
            ],
            [
                'title' => 'Documentation',
                'items' => [
                    ['label' => 'Assets', 'url' => '/agent/assets.php' . $clientQuery, 'icon' => 'desktop', 'badge' => $num_assets ?? 0, 'active' => ['assets.php', 'client_asset_details.php', 'asset_details.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_support')],
                    ['label' => 'Licenses', 'url' => '/agent/software.php' . $clientQuery, 'icon' => 'cube', 'badge' => $num_software ?? 0, 'active' => ['software.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_support')],
                    ['label' => 'Credentials', 'url' => '/agent/credentials.php' . $clientQuery, 'icon' => 'key', 'badge' => $num_credentials ?? 0, 'active' => ['credentials.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_credential')],
                    ['label' => 'Networks', 'url' => '/agent/networks.php' . $clientQuery, 'icon' => 'network-wired', 'badge' => $num_networks ?? 0, 'active' => ['networks.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_support')],
                    ['label' => 'Racks', 'url' => '/agent/racks.php' . $clientQuery, 'icon' => 'server', 'badge' => $num_racks ?? 0, 'active' => ['racks.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_support')],
                    ['label' => 'Certificates', 'url' => '/agent/certificates.php' . $clientQuery, 'icon' => 'lock', 'badge' => $num_certificates ?? 0, 'active' => ['certificates.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_support')],
                    ['label' => 'Domains', 'url' => '/agent/domains.php' . $clientQuery, 'icon' => 'globe', 'badge' => $num_domains ?? 0, 'active' => ['domains.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_support')],
                    ['label' => 'Services', 'url' => '/agent/services.php' . $clientQuery, 'icon' => 'stream', 'badge' => $num_services ?? 0, 'active' => ['services.php'], 'visible' => $config_module_enable_itdoc == 1 && n45_has_permission('module_support')],
                    ['label' => 'Files', 'url' => '/agent/files.php' . $clientQuery, 'icon' => 'folder', 'badge' => $num_files ?? 0, 'active' => ['files.php'], 'visible' => $config_module_enable_itdoc == 1],
                ],
            ],
            [
                'title' => 'Billing',
                'items' => [
                    ['label' => 'Invoices', 'url' => '/agent/invoices.php' . $clientQuery, 'icon' => 'file-invoice', 'badge' => $num_invoices ?? 0, 'active' => ['invoices.php', 'invoice.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_sales')],
                    ['label' => 'Recurring Invoices', 'url' => '/agent/recurring_invoices.php' . $clientQuery, 'icon' => 'redo-alt', 'badge' => $num_recurring_invoices ?? 0, 'active' => ['recurring_invoices.php', 'recurring_invoice.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_sales')],
                    ['label' => 'Quotes', 'url' => '/agent/quotes.php' . $clientQuery, 'icon' => 'comment-dollar', 'badge' => $num_quotes ?? 0, 'active' => ['quotes.php', 'quote.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_sales')],
                    ['label' => 'Payments', 'url' => '/agent/payments.php' . $clientQuery, 'icon' => 'credit-card', 'badge' => $num_payments ?? 0, 'active' => ['payments.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Trips', 'url' => '/agent/trips.php' . $clientQuery, 'icon' => 'route', 'badge' => $num_trips ?? 0, 'active' => ['trips.php'], 'visible' => $config_module_enable_accounting == 1],
                ],
            ],
        ];

        $footer = '<a href="/agent/clients.php">' . n45_icon('arrow-left') . '<span>Back to clients</span></a>';

        return n45_sidebar($client_abbreviation ?: 'Client', 'Client workspace', '/agent/clients.php', $groups, $footer);
    }
}

if (!function_exists('n45_render_client_overview_sidebar')) {
    function n45_render_client_overview_sidebar()
    {
        global $num_contacts, $num_locations, $num_assets, $num_software, $num_credentials, $num_networks,
            $num_certificates, $num_domains, $num_services;

        $groups = [
            [
                'title' => 'Client Overview',
                'items' => [
                    ['label' => 'Contacts', 'url' => 'contacts.php', 'icon' => 'address-book', 'badge' => $num_contacts ?? 0, 'active' => ['contacts.php', 'contact_details.php'], 'visible' => n45_has_permission('module_support')],
                    ['label' => 'Locations', 'url' => 'locations.php', 'icon' => 'map-marker-alt', 'badge' => $num_locations ?? 0, 'active' => ['locations.php'], 'visible' => n45_has_permission('module_support')],
                    ['label' => 'Assets', 'url' => 'assets.php', 'icon' => 'desktop', 'badge' => $num_assets ?? 0, 'active' => ['assets.php'], 'visible' => n45_has_permission('module_support')],
                    ['label' => 'Licenses', 'url' => 'software.php', 'icon' => 'cube', 'badge' => $num_software ?? 0, 'active' => ['software.php'], 'visible' => n45_has_permission('module_support')],
                    ['label' => 'Credentials', 'url' => 'credentials.php', 'icon' => 'key', 'badge' => $num_credentials ?? 0, 'active' => ['credentials.php'], 'visible' => n45_has_permission('module_support')],
                    ['label' => 'Networks', 'url' => 'networks.php', 'icon' => 'network-wired', 'badge' => $num_networks ?? 0, 'active' => ['networks.php'], 'visible' => n45_has_permission('module_support')],
                    ['label' => 'Certificates', 'url' => 'certificates.php', 'icon' => 'lock', 'badge' => $num_certificates ?? 0, 'active' => ['certificates.php'], 'visible' => n45_has_permission('module_support')],
                    ['label' => 'Domains', 'url' => 'domains.php', 'icon' => 'globe', 'badge' => $num_domains ?? 0, 'active' => ['domains.php'], 'visible' => n45_has_permission('module_support')],
                    ['label' => 'Services', 'url' => 'services.php', 'icon' => 'stream', 'badge' => $num_services ?? 0, 'active' => ['services.php'], 'visible' => n45_has_permission('module_support')],
                ],
            ],
        ];

        $footer = '<a href="clients.php">' . n45_icon('arrow-left') . '<span>Back to clients</span></a>';

        return n45_sidebar('Client Overview', 'All organizations', 'clients.php', $groups, $footer);
    }
}

if (!function_exists('n45_render_user_sidebar')) {
    function n45_render_user_sidebar()
    {
        global $config_start_page;

        $groups = [
            [
                'title' => 'Account',
                'items' => [
                    ['label' => 'Details', 'url' => '/agent/user/user_details.php', 'icon' => 'user', 'active' => ['user_details.php']],
                    ['label' => 'Security', 'url' => '/agent/user/user_security.php', 'icon' => 'shield-alt', 'active' => ['user_security.php']],
                    ['label' => 'Preferences', 'url' => '/agent/user/user_preferences.php', 'icon' => 'cogs', 'active' => ['user_preferences.php']],
                    ['label' => 'Activity', 'url' => '/agent/user/user_activity.php', 'icon' => 'clock', 'active' => ['user_activity.php']],
                ],
            ],
        ];

        $footer = '<a href="/agent/' . n45_attr($config_start_page) . '">' . n45_icon('arrow-left') . '<span>Back to workspace</span></a>';

        return n45_sidebar('Account', 'User settings', '/agent/' . $config_start_page, $groups, $footer);
    }
}

if (!function_exists('n45_render_reports_sidebar')) {
    function n45_render_reports_sidebar()
    {
        global $config_start_page, $config_module_enable_accounting, $config_module_enable_ticketing;

        $groups = [
            [
                'title' => 'Financial',
                'items' => [
                    ['label' => 'Income', 'url' => '/agent/reports/income_summary.php', 'icon' => 'circle', 'active' => ['income_summary.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Income by Client', 'url' => '/agent/reports/income_by_client.php', 'icon' => 'user', 'active' => ['income_by_client.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Recurring Income', 'url' => '/agent/reports/recurring_by_client.php', 'icon' => 'sync', 'active' => ['recurring_by_client.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Clients with Balance', 'url' => '/agent/reports/clients_with_balance.php', 'icon' => 'exclamation-triangle', 'active' => ['clients_with_balance.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Expense', 'url' => '/agent/reports/expense_summary.php', 'icon' => 'credit-card', 'active' => ['expense_summary.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Expense by Vendor', 'url' => '/agent/reports/expense_by_vendor.php', 'icon' => 'building', 'active' => ['expense_by_vendor.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Tax Summary', 'url' => '/agent/reports/tax_summary.php', 'icon' => 'percent', 'active' => ['tax_summary.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Profit & Loss', 'url' => '/agent/reports/profit_loss.php', 'icon' => 'file-invoice-dollar', 'active' => ['profit_loss.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Unbilled Tickets', 'url' => '/agent/reports/tickets_unbilled.php', 'icon' => 'life-ring', 'active' => ['tickets_unbilled.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                    ['label' => 'Client Time Detail', 'url' => '/agent/reports/client_ticket_time_detail.php', 'icon' => 'clock', 'active' => ['client_ticket_time_detail.php'], 'visible' => $config_module_enable_accounting == 1 && n45_has_permission('module_financial')],
                ],
            ],
            [
                'title' => 'Technical',
                'items' => [
                    ['label' => 'Tickets', 'url' => '/agent/reports/ticket_summary.php', 'icon' => 'life-ring', 'active' => ['ticket_summary.php'], 'visible' => $config_module_enable_ticketing && n45_has_permission('module_support')],
                    ['label' => 'Tickets by Client', 'url' => '/agent/reports/ticket_by_client.php', 'icon' => 'life-ring', 'active' => ['ticket_by_client.php'], 'visible' => $config_module_enable_ticketing && n45_has_permission('module_support')],
                    ['label' => 'Time by Technician', 'url' => '/agent/reports/time_by_tech.php', 'icon' => 'stopwatch', 'active' => ['time_by_tech.php'], 'visible' => $config_module_enable_ticketing && n45_has_permission('module_support')],
                    ['label' => 'Credential Rotation', 'url' => '/agent/reports/credential_rotation.php', 'icon' => 'key', 'active' => ['credential_rotation.php'], 'visible' => n45_has_permission('module_credential')],
                ],
            ],
        ];

        $custom = n45_custom_nav_items(5);
        if (!empty($custom)) {
            $groups[] = ['title' => 'Custom', 'items' => $custom];
        }

        $footer = '<a href="/agent/' . n45_attr($config_start_page) . '">' . n45_icon('arrow-left') . '<span>Back to workspace</span></a>';

        return n45_sidebar('Reports', 'Intelligence', '/agent/' . $config_start_page, $groups, $footer);
    }
}

if (!function_exists('n45_render_admin_sidebar')) {
    function n45_render_admin_sidebar()
    {
        global $config_start_page, $config_module_enable_accounting, $config_module_enable_ticketing,
            $config_module_enable_itdoc, $config_client_portal_enable;

        $groups = [
            [
                'title' => 'Access',
                'items' => [
                    ['label' => 'Users', 'url' => '/admin/users.php', 'icon' => 'users', 'active' => ['users.php']],
                    ['label' => 'Roles', 'url' => '/admin/roles.php', 'icon' => 'user-shield', 'active' => ['roles.php']],
                    ['label' => 'API Keys', 'url' => '/admin/api_keys.php', 'icon' => 'key', 'active' => ['api_keys.php']],
                    ['label' => 'Integrations', 'url' => '/admin/integrations.php', 'icon' => 'plug', 'active' => ['integrations.php']],
                ],
            ],
            [
                'title' => 'Tags & Categories',
                'items' => [
                    ['label' => 'Tags', 'url' => '/admin/tag.php', 'icon' => 'tags', 'active' => ['tag.php']],
                    ['label' => 'Categories', 'url' => '/admin/category.php', 'icon' => 'list-ul', 'active' => ['category.php']],
                    ['label' => 'Taxes', 'url' => '/admin/tax.php', 'icon' => 'balance-scale', 'active' => ['tax.php'], 'visible' => $config_module_enable_accounting],
                    ['label' => 'Payment Methods', 'url' => '/admin/payment_method.php', 'icon' => 'hand-holding-usd', 'active' => ['payment_method.php'], 'visible' => $config_module_enable_accounting],
                    ['label' => 'Payment Providers', 'url' => '/admin/payment_provider.php', 'icon' => 'credit-card', 'active' => ['payment_provider.php', 'saved_payment_method.php'], 'visible' => $config_module_enable_accounting],
                    ['label' => 'AI Providers', 'url' => '/admin/ai_provider.php', 'icon' => 'robot', 'active' => ['ai_provider.php', 'ai_model.php']],
                    ['label' => 'Ticket Statuses', 'url' => '/admin/ticket_status.php', 'icon' => 'info-circle', 'active' => ['ticket_status.php'], 'visible' => $config_module_enable_ticketing],
                    ['label' => 'Custom Links', 'url' => '/admin/custom_link.php', 'icon' => 'external-link-alt', 'active' => ['custom_link.php']],
                ],
            ],
            [
                'title' => 'Templates',
                'items' => [
                    ['label' => 'Project Templates', 'url' => '/admin/project_template.php', 'icon' => 'project-diagram', 'active' => ['project_template.php', 'project_template_details.php'], 'visible' => $config_module_enable_itdoc],
                    ['label' => 'Ticket Templates', 'url' => '/admin/ticket_template.php', 'icon' => 'life-ring', 'active' => ['ticket_template.php', 'ticket_template_details.php'], 'visible' => $config_module_enable_itdoc],
                    ['label' => 'Vendor Templates', 'url' => '/admin/vendor_template.php', 'icon' => 'building', 'active' => ['vendor_template.php'], 'visible' => $config_module_enable_itdoc],
                    ['label' => 'License Templates', 'url' => '/admin/software_template.php', 'icon' => 'rocket', 'active' => ['software_template.php'], 'visible' => $config_module_enable_itdoc],
                    ['label' => 'Document Templates', 'url' => '/admin/document_template.php', 'icon' => 'file-alt', 'active' => ['document_template.php', 'document_template_details.php'], 'visible' => $config_module_enable_itdoc],
                ],
            ],
            [
                'title' => 'Maintenance',
                'items' => [
                    ['label' => 'Mail Queue', 'url' => '/admin/mail_queue.php', 'icon' => 'mail-bulk', 'active' => ['mail_queue.php']],
                    ['label' => 'Audit Logs', 'url' => '/admin/audit_log.php', 'icon' => 'history', 'active' => ['audit_log.php']],
                    ['label' => 'App Logs', 'url' => '/admin/app_log.php', 'icon' => 'history', 'active' => ['app_log.php']],
                    ['label' => 'Backup', 'url' => '/admin/backup.php', 'icon' => 'cloud-upload-alt', 'active' => ['backup.php']],
                    ['label' => 'Debug', 'url' => '/admin/debug.php', 'icon' => 'bug', 'active' => ['debug.php']],
                    ['label' => 'Update', 'url' => '/admin/update.php', 'icon' => 'download', 'active' => ['update.php']],
                ],
            ],
            [
                'title' => 'Settings',
                'items' => [
                    ['label' => 'Company Details', 'url' => '/admin/settings_company.php', 'icon' => 'briefcase', 'active' => ['settings_company.php']],
                    ['label' => 'Localization', 'url' => '/admin/settings_localization.php', 'icon' => 'globe', 'active' => ['settings_localization.php']],
                    ['label' => 'Theme', 'url' => '/admin/settings_theme.php', 'icon' => 'paint-brush', 'active' => ['settings_theme.php']],
                    ['label' => 'Security', 'url' => '/admin/settings_security.php', 'icon' => 'shield-alt', 'active' => ['settings_security.php']],
                    ['label' => 'Mail', 'url' => '/admin/settings_mail.php', 'icon' => 'envelope', 'active' => ['settings_mail.php']],
                    ['label' => 'Notifications', 'url' => '/admin/settings_notification.php', 'icon' => 'bell', 'active' => ['settings_notification.php']],
                    ['label' => 'Defaults', 'url' => '/admin/settings_default.php', 'icon' => 'cogs', 'active' => ['settings_default.php']],
                    ['label' => 'Invoice', 'url' => '/admin/settings_invoice.php', 'icon' => 'file-invoice', 'active' => ['settings_invoice.php'], 'visible' => $config_module_enable_accounting],
                    ['label' => 'Quote', 'url' => '/admin/settings_quote.php', 'icon' => 'comment-dollar', 'active' => ['settings_quote.php'], 'visible' => $config_module_enable_accounting],
                    ['label' => 'Project', 'url' => '/admin/settings_project.php', 'icon' => 'project-diagram', 'active' => ['settings_project.php'], 'visible' => $config_module_enable_ticketing],
                    ['label' => 'Ticket', 'url' => '/admin/settings_ticket.php', 'icon' => 'life-ring', 'active' => ['settings_ticket.php'], 'visible' => $config_module_enable_ticketing],
                    ['label' => 'Identity Provider', 'url' => '/admin/identity_provider.php', 'icon' => 'fingerprint', 'active' => ['identity_provider.php'], 'visible' => $config_client_portal_enable],
                    ['label' => 'Telemetry', 'url' => '/admin/settings_telemetry.php', 'icon' => 'satellite-dish', 'active' => ['settings_telemetry.php']],
                    ['label' => 'Modules', 'url' => '/admin/settings_module.php', 'icon' => 'cube', 'active' => ['settings_module.php']],
                ],
            ],
        ];

        $custom = n45_custom_nav_items(4);
        if (!empty($custom)) {
            $groups[] = ['title' => 'Custom', 'items' => $custom];
        }

        $footer = '<a href="/agent/' . n45_attr($config_start_page) . '">' . n45_icon('arrow-left') . '<span>Back to workspace</span></a>';

        return n45_sidebar('Administration', 'System controls', '/agent/' . $config_start_page, $groups, $footer);
    }
}
