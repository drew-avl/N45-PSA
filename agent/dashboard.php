<?php
require_once "includes/inc_all.php";

// Get current year or the selected year
$year = isset($_GET['year']) ? intval($_GET['year']) : date('Y');

// Update user settings based on GET parameters
if (isset($_GET['enable_financial'])) {
    $enable_financial = intval($_GET['enable_financial']);
    mysqli_query($mysqli, "UPDATE user_settings SET user_config_dashboard_financial_enable = $enable_financial WHERE user_id = $session_user_id");
}

if (isset($_GET['enable_technical'])) {
    $enable_technical = intval($_GET['enable_technical']);
    mysqli_query($mysqli, "UPDATE user_settings SET user_config_dashboard_technical_enable = $enable_technical WHERE user_id = $session_user_id");
}

// Fetch User Dashboard Settings
$sql_user_dashboard_settings = mysqli_query($mysqli, "SELECT * FROM user_settings WHERE user_id = $session_user_id");
$row = mysqli_fetch_assoc($sql_user_dashboard_settings);
$user_config_dashboard_financial_enable = intval($row['user_config_dashboard_financial_enable']);
$user_config_dashboard_technical_enable = intval($row['user_config_dashboard_technical_enable']);

// Get unique years from expenses, payments, invoices, revenues, tickets, clients, and users
$sql_years_select = mysqli_query($mysqli, "
    SELECT YEAR(expense_date) AS all_years FROM expenses
    UNION DISTINCT SELECT YEAR(payment_date) FROM payments
    UNION DISTINCT SELECT YEAR(revenue_date) FROM revenues
    UNION DISTINCT SELECT YEAR(invoice_date) FROM invoices
    UNION DISTINCT SELECT YEAR(ticket_created_at) FROM tickets
    UNION DISTINCT SELECT YEAR(client_created_at) FROM clients
    UNION DISTINCT SELECT YEAR(user_created_at) FROM users
    ORDER BY all_years DESC
");
?>

<div class="n45-dashboard-toolbar">
    <form>
        <input type="hidden" name="enable_financial" value="0">
        <input type="hidden" name="enable_technical" value="0">

        <label for="year" class="mb-0">Year</label>
        <select id="year" onchange="this.form.submit()" class="form-control" name="year">
            <?php while ($row = mysqli_fetch_assoc($sql_years_select)) {
                $year_select = $row['all_years'];
                if (empty($year_select)) {
                    $year_select = date('Y');
                }
            ?>
                <option value="<?php echo $year_select; ?>" <?php if ($year == $year_select) { echo "selected"; } ?>>
                    <?php echo $year_select; ?>
                </option>
            <?php } ?>
        </select>

        <?php if ($session_user_role == 1 || ($session_user_role == 3 && $config_module_enable_accounting == 1)) { ?>
            <div class="custom-control custom-switch n45-toggle">
                <input type="checkbox" onchange="this.form.submit()" class="custom-control-input" id="customSwitch1" name="enable_financial" value="1" <?php if ($user_config_dashboard_financial_enable == 1) { echo "checked"; } ?>>
                <label class="custom-control-label" for="customSwitch1">Financial</label>
            </div>
        <?php } ?>

        <?php if ($session_user_role >= 2 && $config_module_enable_ticketing == 1) { ?>
            <div class="custom-control custom-switch n45-toggle">
                <input type="checkbox" onchange="this.form.submit()" class="custom-control-input" id="customSwitch2" name="enable_technical" value="1" <?php if ($user_config_dashboard_technical_enable == 1) { echo "checked"; } ?>>
                <label class="custom-control-label" for="customSwitch2">Technical</label>
            </div>
        <?php } ?>
    </form>
</div>

<?php
if ($user_config_dashboard_financial_enable == 1) {

    // Fetch financial data for the dashboard
    // Define variables to avoid errors in logs
    $largest_income_month = 0;

    $sql_total_payments_to_invoices = mysqli_query($mysqli, "SELECT SUM(payment_amount) AS total_payments_to_invoices FROM payments WHERE YEAR(payment_date) = $year");
    $row = mysqli_fetch_assoc($sql_total_payments_to_invoices);
    $total_payments_to_invoices = floatval($row['total_payments_to_invoices']);

    $sql_total_revenues = mysqli_query($mysqli, "SELECT SUM(revenue_amount) AS total_revenues FROM revenues WHERE YEAR(revenue_date) = $year AND revenue_category_id > 0");
    $row = mysqli_fetch_assoc($sql_total_revenues);
    $total_revenues = floatval($row['total_revenues']);

    $total_income = $total_payments_to_invoices + $total_revenues;

    $sql_total_expenses = mysqli_query($mysqli, "SELECT SUM(expense_amount) AS total_expenses FROM expenses WHERE expense_vendor_id > 0 AND YEAR(expense_date) = $year");
    $row = mysqli_fetch_assoc($sql_total_expenses);
    $total_expenses = floatval($row['total_expenses']);

    $sql_invoice_totals = mysqli_query($mysqli, "SELECT SUM(invoice_amount) AS invoice_totals FROM invoices WHERE invoice_status != 'Draft' AND invoice_status != 'Cancelled' AND invoice_status != 'Non-Billable' AND YEAR(invoice_date) = $year");
    $row = mysqli_fetch_assoc($sql_invoice_totals);
    $invoice_totals = floatval($row['invoice_totals']);

    $sql_total_payments_to_invoices_all_years = mysqli_query($mysqli, "SELECT SUM(payment_amount) AS total_payments_to_invoices_all_years FROM payments");
    $row = mysqli_fetch_assoc($sql_total_payments_to_invoices_all_years);
    $total_payments_to_invoices_all_years = floatval($row['total_payments_to_invoices_all_years']);

    $sql_invoice_totals_all_years = mysqli_query($mysqli, "SELECT SUM(invoice_amount) AS invoice_totals_all_years FROM invoices WHERE invoice_status != 'Draft' AND invoice_status != 'Cancelled' AND invoice_status != 'Non-Billable'");
    $row = mysqli_fetch_assoc($sql_invoice_totals_all_years);
    $invoice_totals_all_years = floatval($row['invoice_totals_all_years']);

    $receivables = $invoice_totals_all_years - $total_payments_to_invoices_all_years;

    $profit = $total_income - $total_expenses;

    $sql_accounts = mysqli_query($mysqli, "SELECT * FROM accounts WHERE account_archived_at IS NULL ORDER BY account_name ASC");

    $sql_latest_invoice_payments = mysqli_query($mysqli, "
        SELECT * FROM payments
        JOIN invoices ON payment_invoice_id = invoice_id
        JOIN clients ON invoice_client_id = client_id
        ORDER BY payment_id DESC LIMIT 5
    ");

    $sql_latest_expenses = mysqli_query($mysqli, "
        SELECT * FROM expenses
        JOIN vendors ON expense_vendor_id = vendor_id
        JOIN categories ON expense_category_id = category_id
        ORDER BY expense_id DESC LIMIT 5
    ");

    // Get recurring invoice totals
    $sql_recurring_yearly_total = mysqli_query($mysqli, "SELECT SUM(recurring_invoice_amount) AS recurring_yearly_total FROM recurring_invoices WHERE recurring_invoice_status = 1 AND recurring_invoice_frequency = 'year' AND YEAR(recurring_invoice_created_at) <= $year");
    $row = mysqli_fetch_assoc($sql_recurring_yearly_total);
    $recurring_yearly_total = floatval($row['recurring_yearly_total']);

    $sql_recurring_monthly_total = mysqli_query($mysqli, "SELECT SUM(recurring_invoice_amount) AS recurring_monthly_total FROM recurring_invoices WHERE recurring_invoice_status = 1 AND recurring_invoice_frequency = 'month' AND YEAR(recurring_invoice_created_at) <= $year");
    $row = mysqli_fetch_assoc($sql_recurring_monthly_total);
    $recurring_monthly_total = floatval($row['recurring_monthly_total']) + ($recurring_yearly_total / 12);

    // Recurring expenses totals
    $sql_recurring_expense_yearly_total = mysqli_query($mysqli, "SELECT SUM(recurring_expense_amount) AS recurring_expense_yearly_total FROM recurring_expenses WHERE recurring_expense_status = 1 AND recurring_expense_frequency = 2 AND YEAR(recurring_expense_created_at) <= $year");
    $row = mysqli_fetch_assoc($sql_recurring_expense_yearly_total);
    $recurring_expense_yearly_total = floatval($row['recurring_expense_yearly_total']);

    $sql_recurring_expense_monthly_total = mysqli_query($mysqli, "SELECT SUM(recurring_expense_amount) AS recurring_expense_monthly_total FROM recurring_expenses WHERE recurring_expense_status = 1 AND recurring_expense_frequency = 1 AND YEAR(recurring_expense_created_at) <= $year");
    $row = mysqli_fetch_assoc($sql_recurring_expense_monthly_total);
    $recurring_expense_monthly_total = floatval($row['recurring_expense_monthly_total']) + ($recurring_expense_yearly_total / 12);

    // Get miles driven
    $sql_miles_driven = mysqli_query($mysqli, "SELECT SUM(trip_miles) AS total_miles FROM trips WHERE YEAR(trip_date) = $year");
    $row = mysqli_fetch_assoc($sql_miles_driven);
    $total_miles = floatval($row['total_miles']);

    if ($config_module_enable_ticketing && $config_module_enable_accounting) {
        $sql_unbilled_tickets = mysqli_query($mysqli, "SELECT COUNT(ticket_id) AS unbilled_tickets FROM tickets WHERE ticket_closed_at IS NOT NULL AND ticket_billable = 1 AND ticket_invoice_id = 0 AND YEAR(ticket_created_at) = $year");
        $row = mysqli_fetch_assoc($sql_unbilled_tickets);
        $unbilled_tickets = intval($row['unbilled_tickets']);
    } else {
        $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(recurring_invoice_id) AS recurring_invoices_added FROM recurring_invoices WHERE YEAR(recurring_invoice_created_at) = $year"));
        $recurring_invoices_added = intval($row['recurring_invoices_added']);
    }

    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(client_id) AS clients_added FROM clients WHERE YEAR(client_created_at) = $year AND client_lead = 0 AND client_archived_at IS NULL"));
    $clients_added = intval($row['clients_added']);

    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(client_id) AS leads_added FROM clients WHERE YEAR(client_created_at) = $year AND client_lead = 1 AND client_archived_at IS NULL"));
    $leads_added = intval($row['leads_added']);

    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(vendor_id) AS vendors_added FROM vendors WHERE YEAR(vendor_created_at) = $year AND vendor_client_id = 0 AND vendor_archived_at IS NULL"));
    $vendors_added = intval($row['vendors_added']);
?>
<section class="n45-dashboard-section">
    <?php echo n45_section_header('Financial Operations', "Revenue, expenses, recurring activity, and growth signals for $year."); ?>

    <div class="n45-grid n45-grid--metrics mb-3">
        <?php echo n45_metric_card('Income', numfmt_format_currency($currency_format, $total_income, "$session_company_currency"), "payments.php?dtf=$year-01-01&dtt=$year-12-31", 'hand-holding-usd', 'Receivables: ' . numfmt_format_currency($currency_format, $receivables, "$session_company_currency")); ?>
        <?php echo n45_metric_card('Expenses', numfmt_format_currency($currency_format, $total_expenses, "$session_company_currency"), "expenses.php?dtf=$year-01-01&dtt=$year-12-31", 'shopping-cart', '', 'danger'); ?>
        <?php echo n45_metric_card('Profit', numfmt_format_currency($currency_format, $profit, "$session_company_currency"), 'reports/profit_loss.php', 'balance-scale', '', $profit < 0 ? 'danger' : 'success'); ?>
        <?php echo n45_metric_card('Monthly Recurring Income', numfmt_format_currency($currency_format, $recurring_monthly_total, "$session_company_currency"), 'reports/recurring_by_client.php', 'sync-alt'); ?>
        <?php echo n45_metric_card('Monthly Recurring Expense', numfmt_format_currency($currency_format, $recurring_expense_monthly_total, "$session_company_currency"), 'recurring_expenses.php', 'clock', '', 'warning'); ?>
        <?php if ($config_module_enable_ticketing && $config_module_enable_accounting) { ?>
            <?php echo n45_metric_card('Unbilled Tickets', $unbilled_tickets, 'reports/tickets_unbilled.php', 'ticket-alt'); ?>
        <?php } else { ?>
            <?php echo n45_metric_card('Recurring Invoices Added', $recurring_invoices_added, "recurring_invoices.php?dtf=$year-01-01&dtt=$year-12-31", 'file-invoice'); ?>
        <?php } ?>
        <?php echo n45_metric_card('New Leads', $leads_added, "clients.php?leads=1&dtf=$year-01-01&dtt=$year-12-31", 'users'); ?>
        <?php echo n45_metric_card('New Clients', $clients_added, "clients.php?dtf=$year-01-01&dtt=$year-12-31", 'users'); ?>
        <?php echo n45_metric_card('New Vendors', $vendors_added, "vendors.php?dtf=$year-01-01&dtt=$year-12-31", 'building'); ?>
        <?php echo n45_metric_card('Miles Traveled', number_format($total_miles, 2), "trips.php?dtf=$year-01-01&dtt=$year-12-31", 'route'); ?>
    </div>

    <div class="n45-grid">

        <?php echo n45_panel_start('Cash Flow', 'chart-area', '<a href="reports/income_summary.php" class="n45-topbar-button" title="View income summary"><i class="fas fa-eye"></i></a>'); ?>
            <div class="n45-chart-frame">
                <canvas id="cashFlow"></canvas>
            </div>
        <?php echo n45_panel_end(); ?>

        <div class="n45-grid n45-grid--three">
            <?php echo n45_panel_start('Income by Category', 'chart-pie'); ?>
                <div class="n45-chart-frame n45-chart-frame--sm">
                    <canvas id="incomeByCategoryPieChart"></canvas>
                </div>
            <?php echo n45_panel_end(); ?>

            <?php echo n45_panel_start('Expenses by Category', 'shopping-cart'); ?>
                <div class="n45-chart-frame n45-chart-frame--sm">
                    <canvas id="expenseByCategoryPieChart"></canvas>
                </div>
            <?php echo n45_panel_end(); ?>

            <?php echo n45_panel_start('Expenses by Vendor', 'building'); ?>
                <div class="n45-chart-frame n45-chart-frame--sm">
                    <canvas id="expenseByVendorPieChart"></canvas>
                </div>
            <?php echo n45_panel_end(); ?>
        </div>

        <div class="n45-grid n45-grid--three">
            <?php echo n45_panel_start('Account Balances', 'piggy-bank'); ?>
                <div class="n45-table-wrap">
                    <table class="table">
                        <tbody>
                            <?php while ($row = mysqli_fetch_assoc($sql_accounts)) {
                                $account_id = intval($row['account_id']);
                                $account_name = nullable_htmlentities($row['account_name']);
                                $opening_balance = floatval($row['opening_balance']);
                            ?>
                                <tr>
                                    <td><?php echo $account_name; ?></td>
                                    <?php
                                    $sql_payments = mysqli_query($mysqli, "SELECT SUM(payment_amount) AS total_payments FROM payments WHERE payment_account_id = $account_id");
                                    $row = mysqli_fetch_assoc($sql_payments);
                                    $total_payments = floatval($row['total_payments']);

                                    $sql_revenues = mysqli_query($mysqli, "SELECT SUM(revenue_amount) AS total_revenues FROM revenues WHERE revenue_account_id = $account_id");
                                    $row = mysqli_fetch_assoc($sql_revenues);
                                    $total_revenues = floatval($row['total_revenues']);

                                    $sql_expenses = mysqli_query($mysqli, "SELECT SUM(expense_amount) AS total_expenses FROM expenses WHERE expense_account_id = $account_id");
                                    $row = mysqli_fetch_assoc($sql_expenses);
                                    $total_expenses = floatval($row['total_expenses']);

                                    $balance = $opening_balance + $total_payments + $total_revenues - $total_expenses;

                                    if ($balance == '') {
                                        $balance = '0.00';
                                    }
                                    ?>
                                    <td class="text-right"><?php echo numfmt_format_currency($currency_format, $balance, "$session_company_currency"); ?></td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            <?php echo n45_panel_end(); ?>

            <?php echo n45_panel_start('Latest Income', 'credit-card'); ?>
                <div class="n45-table-wrap">
                    <table class="table table-borderless table-sm">
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Customer</th>
                                <th>Invoice</th>
                                <th class="text-right">Amount</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($row = mysqli_fetch_assoc($sql_latest_invoice_payments)) {
                                $payment_date = nullable_htmlentities($row['payment_date']);
                                $payment_amount = floatval($row['payment_amount']);
                                $invoice_prefix = nullable_htmlentities($row['invoice_prefix']);
                                $invoice_number = intval($row['invoice_number']);
                                $client_name = nullable_htmlentities($row['client_name']);
                            ?>
                                <tr>
                                    <td><?php echo $payment_date; ?></td>
                                    <td><?php echo $client_name; ?></td>
                                    <td><?php echo "$invoice_prefix$invoice_number"; ?></td>
                                    <td class="text-right"><?php echo numfmt_format_currency($currency_format, $payment_amount, "$session_company_currency"); ?></td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            <?php echo n45_panel_end(); ?>

            <?php echo n45_panel_start('Latest Expenses', 'shopping-cart'); ?>
                <div class="n45-table-wrap">
                    <table class="table table-sm table-borderless">
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Vendor</th>
                                <th>Category</th>
                                <th class="text-right">Amount</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($row = mysqli_fetch_assoc($sql_latest_expenses)) {
                                $expense_date = nullable_htmlentities($row['expense_date']);
                                $expense_amount = floatval($row['expense_amount']);
                                $vendor_name = nullable_htmlentities($row['vendor_name']);
                                $category_name = nullable_htmlentities($row['category_name']);
                            ?>
                                <tr>
                                    <td><?php echo $expense_date; ?></td>
                                    <td><?php echo $vendor_name; ?></td>
                                    <td><?php echo $category_name; ?></td>
                                    <td class="text-right"><?php echo numfmt_format_currency($currency_format, $expense_amount, "$session_company_currency"); ?></td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            <?php echo n45_panel_end(); ?>
        </div>

        <?php echo n45_panel_start('Trip Flow', 'route', '<a href="trips.php" class="n45-topbar-button" title="View trips"><i class="fas fa-eye"></i></a>'); ?>
            <div class="n45-chart-frame">
                <canvas id="tripFlow"></canvas>
            </div>
        <?php echo n45_panel_end(); ?>
    </div>
</section>

<?php } ?>

<!-- Technical Dashboard -->

<?php
if ($user_config_dashboard_technical_enable == 1) {

    // Fetch technical data for the dashboard
    $sql_clients = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(client_id) AS clients_added FROM clients WHERE YEAR(client_created_at) = $year"));
    $clients_added = $sql_clients['clients_added'];

    $sql_contacts = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(contact_id) AS contacts_added FROM contacts WHERE YEAR(contact_created_at) = $year"));
    $contacts_added = $sql_contacts['contacts_added'];

    $sql_assets = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(asset_id) AS assets_added FROM assets WHERE YEAR(asset_created_at) = $year"));
    $assets_added = $sql_assets['assets_added'];

    $sql_tickets = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(ticket_id) AS active_tickets FROM tickets WHERE ticket_closed_at IS NULL"));
    $active_tickets = $sql_tickets['active_tickets'];

    $sql_your_tickets = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(ticket_id) AS your_tickets FROM tickets WHERE ticket_closed_at IS NULL AND ticket_assigned_to = $session_user_id"));
    $your_tickets = $sql_your_tickets['your_tickets'];

    $sql_domains_expiring = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(domain_id) AS expiring_domains FROM domains WHERE domain_expire IS NOT NULL AND domain_expire > CURRENT_DATE AND domain_expire < CURRENT_DATE + INTERVAL 30 DAY AND domain_archived_at IS NULL"));
    $expiring_domains = $sql_domains_expiring['expiring_domains'];

    $sql_certs_expiring = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(certificate_id) AS expiring_certs FROM certificates WHERE certificate_expire IS NOT NULL AND certificate_expire > CURRENT_DATE AND certificate_expire < CURRENT_DATE + INTERVAL 30 DAY AND certificate_archived_at IS NULL"));
    $expiring_certificates = $sql_certs_expiring['expiring_certs'];

    $sql_your_tickets = mysqli_query($mysqli, "
        SELECT * FROM tickets
        LEFT JOIN ticket_statuses ON ticket_status = ticket_status_id
        LEFT JOIN clients ON ticket_client_id = client_id
        LEFT JOIN contacts ON ticket_contact_id = contact_id
        WHERE ticket_assigned_to = $session_user_id
        AND ticket_closed_at IS NULL
        ORDER BY ticket_number DESC
    ");
?>

<section class="n45-dashboard-section">
    <?php echo n45_section_header('Technical Operations', "Service desk load, documentation growth, and expiring operational assets for $year."); ?>

    <div class="n45-grid n45-grid--metrics mb-3">
        <?php echo n45_metric_card('New Clients', $clients_added, "clients.php?dtf=$year-01-01&dtt=$year-12-31", 'users'); ?>
        <?php echo n45_metric_card('New Contacts', $contacts_added, 'contacts.php', 'user'); ?>
        <?php echo n45_metric_card('New Assets', $assets_added, 'assets.php', 'desktop'); ?>
        <?php echo n45_metric_card('Active Tickets', $active_tickets, 'tickets.php', 'ticket-alt', '', 'danger'); ?>
        <?php echo n45_metric_card('Expiring Domains', $expiring_domains, 'domains.php?sort=domain_expire&order=ASC', 'globe', 'Next 30 days', 'warning'); ?>
        <?php echo n45_metric_card('Expiring Certificates', $expiring_certificates, 'certificates.php?sort=certificate_expire&order=ASC', 'lock', 'Next 30 days', 'warning'); ?>
    </div>

    <?php echo n45_panel_start('Your Open Tickets', 'life-ring'); ?>
        <?php if ($your_tickets) { ?>
            <div class="n45-table-wrap">
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>Number</th>
                            <th>Subject</th>
                            <th>Client</th>
                            <th>Contact</th>
                            <th>Priority</th>
                            <th>Status</th>
                            <th>Last Response</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = mysqli_fetch_assoc($sql_your_tickets)) {
                            $ticket_id = intval($row['ticket_id']);
                            $ticket_prefix = nullable_htmlentities($row['ticket_prefix']);
                            $ticket_number = intval($row['ticket_number']);
                            $ticket_subject = nullable_htmlentities($row['ticket_subject']);
                            $ticket_priority = nullable_htmlentities($row['ticket_priority']);
                            $ticket_status_name = nullable_htmlentities($row['ticket_status_name']);
                            $ticket_status_color = nullable_htmlentities($row['ticket_status_color']);
                            $ticket_updated_at = nullable_htmlentities($row['ticket_updated_at']);
                            $ticket_updated_at_time_ago = timeAgo($row['ticket_updated_at']);
                            $ticket_updated_at_display = empty($ticket_updated_at) ? "<span class='text-danger'>Never</span>" : $ticket_updated_at_time_ago;

                            $client_id = intval($row['ticket_client_id']);
                            $client_name = nullable_htmlentities($row['client_name']);
                            $contact_id = intval($row['ticket_contact_id']);
                            $contact_name = nullable_htmlentities($row['contact_name']);
                            $has_client = $client_id ? "&client_id=$client_id" : "";
                            $ticket_priority_color = $ticket_priority == "High" ? "danger" : ($ticket_priority == "Medium" ? "warning" : "success");
                            $contact_display = empty($contact_name) ? "-" : "<a href='contact_details.php?client_id=$client_id&contact_id=$contact_id'>$contact_name</a>";
                        ?>
                            <tr class="<?php echo empty($ticket_updated_at) ? 'text-bold' : ''; ?>">
                                <td><a href="ticket.php?ticket_id=<?= "$ticket_id$has_client" ?>"><?= "$ticket_prefix$ticket_number" ?></a></td>
                                <td><a href="ticket.php?ticket_id=<?= "$ticket_id$has_client" ?>"><?= $ticket_subject ?></a></td>
                                <td><a href="tickets.php?client_id=<?php echo $client_id; ?>"><strong><?php echo $client_name; ?></strong></a></td>
                                <td><?php echo $contact_display; ?></td>
                                <td><?php echo n45_status_badge($ticket_priority, $ticket_priority_color); ?></td>
                                <td><?php echo n45_status_badge($ticket_status_name, 'neutral', "background-color: $ticket_status_color; color: #fff;"); ?></td>
                                <td><?php echo $ticket_updated_at_display; ?></td>
                            </tr>
                        <?php } ?>
                    </tbody>
                </table>
            </div>
        <?php } else { ?>
            <?php echo n45_empty_state('No assigned open tickets', 'There are no active tickets assigned to you right now.', 'check-circle'); ?>
        <?php } ?>
    <?php echo n45_panel_end(); ?>
</section>

<?php } ?>

<?php require_once "../includes/footer.php"; ?>

<?php if ($user_config_dashboard_financial_enable == 1) { ?>

<script>
    // N45 defaults for Chart.js v4
    Chart.defaults.font.family = '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
    Chart.defaults.color = '#bdc9da';
    Chart.defaults.borderColor = 'rgba(44, 56, 76, 0.72)';

    // CASH FLOW
    (function () {
        var ctx = document.getElementById("cashFlow");
        if (!ctx) return;

        var myLineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
                datasets: [
                    {
                        label: "Income",
                        fill: false,
                        borderColor: "#2CDCC4",
                        pointBackgroundColor: "#2CDCC4",
                        pointBorderColor: "#2CDCC4",
                        pointHoverRadius: 5,
                        pointHoverBackgroundColor: "#2CDCC4",
                        pointBorderWidth: 2,
                        data: [
                            <?php
                            for ($month = 1; $month <= 12; $month++) {
                                $sql_payments = mysqli_query($mysqli, "SELECT SUM(payment_amount) AS payment_amount_for_month FROM payments, invoices WHERE payment_invoice_id = invoice_id AND YEAR(payment_date) = $year AND MONTH(payment_date) = $month");
                                $row = mysqli_fetch_assoc($sql_payments);
                                $payments_for_month = floatval($row['payment_amount_for_month']);

                                $sql_revenues = mysqli_query($mysqli, "SELECT SUM(revenue_amount) AS revenue_amount_for_month FROM revenues WHERE revenue_category_id > 0 AND YEAR(revenue_date) = $year AND MONTH(revenue_date) = $month");
                                $row = mysqli_fetch_assoc($sql_revenues);
                                $revenues_for_month = floatval($row['revenue_amount_for_month']);

                                $income_for_month = $payments_for_month + $revenues_for_month;

                                if ($income_for_month > 0 && $income_for_month > $largest_income_month) {
                                    $largest_income_month = $income_for_month;
                                }
                                echo "$income_for_month,";
                            }
                            ?>
                        ],
                    },
                    {
                        label: "LY Income",
                        fill: false,
                        borderColor: "#34C4E8",
                        pointBackgroundColor: "#34C4E8",
                        pointBorderColor: "#34C4E8",
                        pointHoverRadius: 5,
                        pointHoverBackgroundColor: "#34C4E8",
                        pointBorderWidth: 2,
                        data: [
                            <?php
                            for ($month = 1; $month <= 12; $month++) {
                                $sql_payments = mysqli_query($mysqli, "SELECT SUM(payment_amount) AS payment_amount_for_month FROM payments, invoices WHERE payment_invoice_id = invoice_id AND YEAR(payment_date) = $year-1 AND MONTH(payment_date) = $month");
                                $row = mysqli_fetch_assoc($sql_payments);
                                $payments_for_month = floatval($row['payment_amount_for_month']);

                                $sql_revenues = mysqli_query($mysqli, "SELECT SUM(revenue_amount) AS revenue_amount_for_month FROM revenues WHERE revenue_category_id > 0 AND YEAR(revenue_date) = $year-1 AND MONTH(revenue_date) = $month");
                                $row = mysqli_fetch_assoc($sql_revenues);
                                $revenues_for_month = floatval($row['revenue_amount_for_month']);

                                $income_for_month = $payments_for_month + $revenues_for_month;

                                if ($income_for_month > 0 && $income_for_month > $largest_income_month) {
                                    $largest_income_month = $income_for_month;
                                }
                                echo "$income_for_month,";
                            }
                            ?>
                        ],
                    },
                    {
                        label: "Projected",
                        fill: false,
                        borderColor: "#7E8DA4",
                        pointBackgroundColor: "#7E8DA4",
                        pointBorderColor: "#7E8DA4",
                        pointHoverRadius: 5,
                        pointHoverBackgroundColor: "#7E8DA4",
                        pointBorderWidth: 2,
                        data: [
                            <?php
                            $largest_invoice_month = 0;
                            for ($month = 1; $month <= 12; $month++) {
                                $sql_projected = mysqli_query($mysqli, "SELECT SUM(invoice_amount) AS invoice_amount_for_month FROM invoices WHERE YEAR(invoice_due) = $year AND MONTH(invoice_due) = $month AND invoice_status != 'Cancelled' AND invoice_status != 'Draft' AND invoice_status != 'Non-Billable'");
                                $row = mysqli_fetch_assoc($sql_projected);
                                $invoice_for_month = floatval($row['invoice_amount_for_month']);

                                if ($invoice_for_month > 0 && $invoice_for_month > $largest_invoice_month) {
                                    $largest_invoice_month = $invoice_for_month;
                                }
                                echo "$invoice_for_month,";
                            }
                            ?>
                        ],
                    },
                    {
                        label: "Expense",
                        tension: 0.3, // v4 name; v2 used lineTension
                        fill: false,
                        borderColor: "#F07082",
                        pointBackgroundColor: "#F07082",
                        pointBorderColor: "#F07082",
                        pointHoverRadius: 5,
                        pointHoverBackgroundColor: "#F07082",
                        pointBorderWidth: 2,
                        data: [
                            <?php
                            $largest_expense_month = 0;
                            for ($month = 1; $month <= 12; $month++) {
                                $sql_expenses = mysqli_query($mysqli, "SELECT SUM(expense_amount) AS expense_amount_for_month FROM expenses WHERE YEAR(expense_date) = $year AND MONTH(expense_date) = $month AND expense_vendor_id > 0");
                                $row = mysqli_fetch_assoc($sql_expenses);
                                $expenses_for_month = floatval($row['expense_amount_for_month']);

                                if ($expenses_for_month > 0 && $expenses_for_month > $largest_expense_month) {
                                    $largest_expense_month = $expenses_for_month;
                                }
                                echo "$expenses_for_month,";
                            }
                            ?>
                        ],
                    }
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { maxTicksLimit: 12 }
                    },
                    y: {
                        beginAtZero: true,
                        min: 0,
                        max: <?php $max = max(1000, $largest_expense_month, $largest_income_month, $largest_invoice_month); echo roundUpToNearestMultiple($max); ?>,
                        ticks: { maxTicksLimit: 5 },
                        grid: { color: "rgba(44, 56, 76, 0.55)" }
                    }
                },
                plugins: {
                    legend: { display: true }
                }
            }
        });
    })();

    // TRIP FLOW
    (function () {
        var ctx = document.getElementById("tripFlow");
        if (!ctx) return;

        var myLineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
                datasets: [{
                    label: "Trip",
                    tension: 0.3,
                    fill: false,
                    backgroundColor: "#34C4E8",
                    borderColor: "#2CDCC4",
                    pointRadius: 5,
                    pointBackgroundColor: "#34C4E8",
                    pointBorderColor: "#34C4E8",
                    pointHoverRadius: 5,
                    pointHoverBackgroundColor: "#2CDCC4",
                    pointBorderWidth: 2,
                    data: [
                        <?php
                        $largest_trip_miles_month = 0;
                        for ($month = 1; $month <= 12; $month++) {
                            $sql_trips = mysqli_query($mysqli, "SELECT SUM(trip_miles) AS trip_miles_for_month FROM trips WHERE YEAR(trip_date) = $year AND MONTH(trip_date) = $month");
                            $row = mysqli_fetch_assoc($sql_trips);
                            $trip_miles_for_month = floatval($row['trip_miles_for_month']);

                            if ($trip_miles_for_month > 0 && $trip_miles_for_month > $largest_trip_miles_month) {
                                $largest_trip_miles_month = $trip_miles_for_month;
                            }
                            echo "$trip_miles_for_month,";
                        }
                        ?>
                    ],
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { maxTicksLimit: 12 }
                    },
                    y: {
                        beginAtZero: true,
                        min: 0,
                        max: <?php $max = max(1000, $largest_trip_miles_month); echo roundUpToNearestMultiple($max); ?>,
                        ticks: { maxTicksLimit: 5 },
                        grid: { color: "rgba(44, 56, 76, 0.55)" }
                    },
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    })();

    // INCOME BY CATEGORY (Doughnut)
    (function () {
        var ctx = document.getElementById("incomeByCategoryPieChart");
        if (!ctx) return;

        var myPieChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [
                    <?php
                    mysqli_query($mysqli, "CREATE TEMPORARY TABLE TopCategories SELECT category_name, category_id, SUM(invoice_amount) AS total_income FROM categories, invoices WHERE invoice_category_id = category_id AND invoice_status = 'Paid' AND YEAR(invoice_date) = $year GROUP BY category_name, category_id ORDER BY total_income DESC LIMIT 5");
                    $sql_categories = mysqli_query($mysqli, "SELECT category_name FROM TopCategories");
                    while ($row = mysqli_fetch_assoc($sql_categories)) {
                        $category_name = json_encode($row['category_name']);
                        echo "$category_name,";
                    }

                    $sql_other_categories = mysqli_query($mysqli, "SELECT SUM(invoices.invoice_amount) AS other_income FROM categories LEFT JOIN TopCategories ON categories.category_id = TopCategories.category_id INNER JOIN invoices ON categories.category_id = invoices.invoice_category_id WHERE TopCategories.category_id IS NULL AND invoice_status = 'Paid' AND YEAR(invoice_date) = $year");
                    $row = mysqli_fetch_assoc($sql_other_categories);
                    $other_income = floatval($row['other_income']);
                    if ($other_income > 0) {
                        echo "'Others',";
                    }
                    ?>
                ],
                datasets: [{
                    data: [
                        <?php
                        $sql_categories = mysqli_query($mysqli, "SELECT total_income FROM TopCategories");
                        while ($row = mysqli_fetch_assoc($sql_categories)) {
                            $total_income = floatval($row['total_income']);
                            echo "$total_income,";
                        }
                        if ($other_income > 0) {
                            echo "$other_income,";
                        }
                        ?>
                    ],
                    backgroundColor: [
                        <?php
                        $sql_categories = mysqli_query($mysqli, "SELECT category_color FROM TopCategories JOIN categories ON TopCategories.category_id = categories.category_id");
                        while ($row = mysqli_fetch_assoc($sql_categories)) {
                            $category_color = json_encode($row['category_color']);
                            echo "$category_color,";
                        }
                        if ($other_income > 0) {
                            echo "'#999999',"; // color for 'Others'
                        }
                        ?>
                    ],
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'right'
                    }
                }
            }
        });
    })();

    // EXPENSE BY CATEGORY (Doughnut)
    (function () {
        var ctx = document.getElementById("expenseByCategoryPieChart");
        if (!ctx) return;

        var myPieChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [
                    <?php
                    mysqli_query($mysqli, "CREATE TEMPORARY TABLE TopExpenseCategories SELECT category_name, category_id, SUM(expense_amount) AS total_expense FROM categories, expenses WHERE expense_category_id = category_id AND expense_vendor_id > 0 AND YEAR(expense_date) = $year GROUP BY category_name, category_id ORDER BY total_expense DESC LIMIT 5");
                    $sql_categories = mysqli_query($mysqli, "SELECT category_name FROM TopExpenseCategories");
                    while ($row = mysqli_fetch_assoc($sql_categories)) {
                        $category_name = json_encode($row['category_name']);
                        echo "$category_name,";
                    }

                    $sql_other_categories = mysqli_query($mysqli, "SELECT SUM(expenses.expense_amount) AS other_expense FROM categories LEFT JOIN TopExpenseCategories ON categories.category_id = TopExpenseCategories.category_id INNER JOIN expenses ON categories.category_id = expenses.expense_category_id WHERE TopExpenseCategories.category_id IS NULL AND expense_vendor_id > 0 AND YEAR(expense_date) = $year");
                    $row = mysqli_fetch_assoc($sql_other_categories);
                    $other_expense = floatval($row['other_expense']);
                    if ($other_expense > 0) {
                        echo "'Others',";
                    }
                    ?>
                ],
                datasets: [{
                    data: [
                        <?php
                        $sql_categories = mysqli_query($mysqli, "SELECT total_expense FROM TopExpenseCategories");
                        while ($row = mysqli_fetch_assoc($sql_categories)) {
                            $total_expense = floatval($row['total_expense']);
                            echo "$total_expense,";
                        }
                        if ($other_expense > 0) {
                            echo "$other_expense,";
                        }
                        ?>
                    ],
                    backgroundColor: [
                        <?php
                        $sql_categories = mysqli_query($mysqli, "SELECT category_color FROM TopExpenseCategories JOIN categories ON TopExpenseCategories.category_id = categories.category_id");
                        while ($row = mysqli_fetch_assoc($sql_categories)) {
                            $category_color = json_encode($row['category_color']);
                            echo "$category_color,";
                        }
                        if ($other_expense > 0) {
                            echo "'#999999',"; // color for 'Others'
                        }
                        ?>
                    ],
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'right'
                    }
                }
            }
        });
    })();

    // EXPENSE BY VENDOR (Doughnut)
    (function () {
        var ctx = document.getElementById("expenseByVendorPieChart");
        if (!ctx) return;

        var myPieChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [
                    <?php
                    mysqli_query($mysqli, "CREATE TEMPORARY TABLE TopVendors SELECT vendor_name, vendor_id, SUM(expense_amount) AS total_expense FROM vendors, expenses WHERE expense_vendor_id = vendor_id AND YEAR(expense_date) = $year GROUP BY vendor_name, vendor_id ORDER BY total_expense DESC LIMIT 5");
                    $sql_vendors = mysqli_query($mysqli, "SELECT vendor_name FROM TopVendors");
                    while ($row = mysqli_fetch_assoc($sql_vendors)) {
                        $vendor_name = json_encode($row['vendor_name']);
                        echo "$vendor_name,";
                    }

                    $sql_other_vendors = mysqli_query($mysqli, "SELECT SUM(expenses.expense_amount) AS other_expense FROM vendors LEFT JOIN TopVendors ON vendors.vendor_id = TopVendors.vendor_id INNER JOIN expenses ON vendors.vendor_id = expenses.expense_vendor_id WHERE TopVendors.vendor_id IS NULL AND YEAR(expense_date) = $year");
                    $row = mysqli_fetch_assoc($sql_other_vendors);
                    $other_expense = floatval($row['other_expense']);
                    if ($other_expense > 0) {
                        echo "'Others',";
                    }
                    ?>
                ],
                datasets: [{
                    data: [
                        <?php
                        $sql_vendors = mysqli_query($mysqli, "SELECT total_expense FROM TopVendors");
                        while ($row = mysqli_fetch_assoc($sql_vendors)) {
                            $total_expense = floatval($row['total_expense']);
                            echo "$total_expense,";
                        }
                        if ($other_expense > 0) {
                            echo "$other_expense,";
                        }
                        ?>
                    ],
                    backgroundColor: [
                        <?php
                        $sql_vendors = mysqli_query($mysqli, "SELECT vendor_id FROM TopVendors");
                        while ($row = mysqli_fetch_assoc($sql_vendors)) {
                            // Generate random color for each vendor
                            echo "'#" . substr(md5(rand()), 0, 6) . "',";
                        }
                        if ($other_expense > 0) {
                            echo "'#999999',"; // color for 'Others'
                        }
                        ?>
                    ],
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'right'
                    }
                }
            }
        });
    })();
</script>

<?php } ?>
