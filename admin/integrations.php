<?php

// Default Column Sortby Filter
$sort = "integration_name";
$order = "ASC";

require_once "includes/inc_all_admin.php";

$allowed_sorts = [
    'integration_name',
    'integration_provider',
    'integration_status',
    'integration_health_status',
    'integration_last_success_at',
    'integration_updated_at',
];

if (!in_array($sort, $allowed_sorts, true)) {
    $sort = 'integration_name';
}

$order = strtoupper($order) === 'DESC' ? 'DESC' : 'ASC';

function n45AdminTableExists(mysqli $mysqli, string $table): bool
{
    $statement = mysqli_prepare(
        $mysqli,
        'SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?'
    );

    if ($statement === false) {
        return false;
    }

    mysqli_stmt_bind_param($statement, 's', $table);
    mysqli_stmt_execute($statement);
    mysqli_stmt_bind_result($statement, $count);
    mysqli_stmt_fetch($statement);
    mysqli_stmt_close($statement);

    return (int) $count > 0;
}

function n45IntegrationCount(mysqli $mysqli, string $table): int
{
    if (!n45AdminTableExists($mysqli, $table)) {
        return 0;
    }

    $result = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM `$table`");
    if ($result === false) {
        return 0;
    }

    $row = mysqli_fetch_assoc($result);
    mysqli_free_result($result);

    return (int) ($row['count'] ?? 0);
}

function n45IntegrationStatusBadge(string $status): string
{
    $status = strtolower($status);
    $classes = [
        'active' => 'success',
        'enabled' => 'success',
        'healthy' => 'success',
        'warning' => 'warning',
        'degraded' => 'warning',
        'queued' => 'info',
        'running' => 'info',
        'pending' => 'secondary',
        'disabled' => 'secondary',
        'failed' => 'danger',
        'error' => 'danger',
        'unknown' => 'secondary',
    ];

    $class = $classes[$status] ?? 'secondary';

    return '<span class="badge badge-' . $class . '">' . nullable_htmlentities(ucwords(str_replace('_', ' ', $status))) . '</span>';
}

$integration_tables_ready = n45AdminTableExists($mysqli, 'integrations');
$integration_count = n45IntegrationCount($mysqli, 'integrations');
$tenant_count = n45IntegrationCount($mysqli, 'integration_tenants');
$client_mapping_count = n45IntegrationCount($mysqli, 'integration_client_mappings');
$asset_mapping_count = n45IntegrationCount($mysqli, 'integration_asset_mappings');
$open_event_count = 0;
$queued_job_count = 0;
$recent_events = [];
$integrations = null;
$num_rows = [0];

if ($integration_tables_ready) {
    $escaped_q = mysqli_real_escape_string($mysqli, $q);
    $sql = mysqli_query(
        $mysqli,
        "SELECT SQL_CALC_FOUND_ROWS *
        FROM integrations
        WHERE (
            integration_name LIKE '%$escaped_q%'
            OR integration_provider LIKE '%$escaped_q%'
            OR integration_status LIKE '%$escaped_q%'
            OR integration_health_status LIKE '%$escaped_q%'
        )
        ORDER BY $sort $order
        LIMIT $record_from, $record_to"
    );

    if ($sql !== false) {
        $integrations = $sql;
        $num_rows = mysqli_fetch_row(mysqli_query($mysqli, "SELECT FOUND_ROWS()"));
    }

    if (n45AdminTableExists($mysqli, 'integration_events')) {
        $event_result = mysqli_query(
            $mysqli,
            "SELECT COUNT(*) AS count
            FROM integration_events
            WHERE integration_event_status IN ('new', 'open', 'pending')"
        );
        if ($event_result !== false) {
            $event_row = mysqli_fetch_assoc($event_result);
            $open_event_count = (int) ($event_row['count'] ?? 0);
            mysqli_free_result($event_result);
        }

        $recent_event_result = mysqli_query(
            $mysqli,
            "SELECT integration_events.*, integrations.integration_name, integrations.integration_provider
            FROM integration_events
            LEFT JOIN integrations ON integration_events.integration_id = integrations.integration_id
            ORDER BY integration_event_created_at DESC
            LIMIT 5"
        );

        if ($recent_event_result !== false) {
            while ($row = mysqli_fetch_assoc($recent_event_result)) {
                $recent_events[] = $row;
            }
            mysqli_free_result($recent_event_result);
        }
    }

    if (n45AdminTableExists($mysqli, 'integration_jobs')) {
        $job_result = mysqli_query(
            $mysqli,
            "SELECT COUNT(*) AS count
            FROM integration_jobs
            WHERE integration_job_status IN ('queued', 'running', 'retry')"
        );
        if ($job_result !== false) {
            $job_row = mysqli_fetch_assoc($job_result);
            $queued_job_count = (int) ($job_row['count'] ?? 0);
            mysqli_free_result($job_result);
        }
    }
}

$planned_providers = [
    [
        'name' => 'Level.io',
        'description' => 'Device inventory, remote access, monitoring, and asset context.',
        'icon' => 'desktop',
    ],
    [
        'name' => 'CIPP',
        'description' => 'Microsoft 365 tenant, user, policy, and Entra operational context.',
        'icon' => 'cloud',
    ],
    [
        'name' => 'SentinelOne',
        'description' => 'Endpoint security alerts, incidents, device posture, and response actions.',
        'icon' => 'shield-alt',
    ],
];

?>

<div class="row">
    <div class="col-md-3 col-sm-6">
        <div class="info-box">
            <span class="info-box-icon bg-primary"><i class="fas fa-fw fa-plug"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Integrations</span>
                <span class="info-box-number"><?php echo $integration_count; ?></span>
            </div>
        </div>
    </div>
    <div class="col-md-3 col-sm-6">
        <div class="info-box">
            <span class="info-box-icon bg-info"><i class="fas fa-fw fa-building"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Tenants</span>
                <span class="info-box-number"><?php echo $tenant_count; ?></span>
            </div>
        </div>
    </div>
    <div class="col-md-3 col-sm-6">
        <div class="info-box">
            <span class="info-box-icon bg-success"><i class="fas fa-fw fa-link"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Mappings</span>
                <span class="info-box-number"><?php echo $client_mapping_count + $asset_mapping_count; ?></span>
            </div>
        </div>
    </div>
    <div class="col-md-3 col-sm-6">
        <div class="info-box">
            <span class="info-box-icon bg-warning"><i class="fas fa-fw fa-stream"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Open Events</span>
                <span class="info-box-number"><?php echo $open_event_count; ?></span>
            </div>
        </div>
    </div>
</div>

<?php if (!$integration_tables_ready) { ?>
    <div class="alert alert-warning">
        <h5><i class="fas fa-fw fa-exclamation-triangle mr-2"></i>Integration migration pending</h5>
        <p class="mb-0">
            Run the N45 migrations to create the shared integration framework tables before configuring providers.
        </p>
    </div>
<?php } ?>

<div class="row">
    <?php foreach ($planned_providers as $provider) { ?>
        <div class="col-lg-4">
            <div class="card card-outline card-secondary h-100">
                <div class="card-body">
                    <div class="d-flex align-items-start">
                        <div class="mr-3">
                            <span class="btn btn-default disabled">
                                <i class="fas fa-fw fa-<?php echo nullable_htmlentities($provider['icon']); ?>"></i>
                            </span>
                        </div>
                        <div>
                            <h5 class="mb-1"><?php echo nullable_htmlentities($provider['name']); ?></h5>
                            <p class="text-muted mb-2"><?php echo nullable_htmlentities($provider['description']); ?></p>
                            <span class="badge badge-secondary">Adapter pending</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    <?php } ?>
</div>

<div class="card card-dark">
    <div class="card-header py-2">
        <h3 class="card-title mt-2"><i class="fas fa-fw fa-plug mr-2"></i>Native Integrations</h3>
        <div class="card-tools mt-2">
            <span class="badge badge-secondary">Foundation</span>
        </div>
    </div>

    <div class="card-body">
        <form autocomplete="off">
            <div class="row">
                <div class="col-md-4">
                    <div class="input-group mb-3 mb-md-0">
                        <input type="search" class="form-control" name="q" value="<?php if (isset($q)) { echo stripslashes(nullable_htmlentities($q)); } ?>" placeholder="Search integrations">
                        <div class="input-group-append">
                            <button class="btn btn-primary"><i class="fa fa-search"></i></button>
                        </div>
                    </div>
                </div>
                <div class="col-md-8 text-md-right">
                    <span class="text-muted">
                        <i class="fas fa-fw fa-info-circle mr-1"></i>
                        Provider setup forms and sync workers will build on this framework.
                    </span>
                </div>
            </div>
        </form>
        <hr>

        <div class="table-responsive-sm">
            <table class="table table-striped table-borderless table-hover">
                <thead class="text-dark <?php if ($num_rows[0] == 0) { echo "d-none"; } ?>">
                <tr>
                    <th>
                        <a class="text-dark" href="?<?php echo $url_query_strings_sort; ?>&sort=integration_name&order=<?php echo $disp; ?>">
                            Name <?php if ($sort == 'integration_name') { echo $order_icon; } ?>
                        </a>
                    </th>
                    <th>
                        <a class="text-dark" href="?<?php echo $url_query_strings_sort; ?>&sort=integration_provider&order=<?php echo $disp; ?>">
                            Provider <?php if ($sort == 'integration_provider') { echo $order_icon; } ?>
                        </a>
                    </th>
                    <th>
                        <a class="text-dark" href="?<?php echo $url_query_strings_sort; ?>&sort=integration_status&order=<?php echo $disp; ?>">
                            Status <?php if ($sort == 'integration_status') { echo $order_icon; } ?>
                        </a>
                    </th>
                    <th>
                        <a class="text-dark" href="?<?php echo $url_query_strings_sort; ?>&sort=integration_health_status&order=<?php echo $disp; ?>">
                            Health <?php if ($sort == 'integration_health_status') { echo $order_icon; } ?>
                        </a>
                    </th>
                    <th>Last Success</th>
                    <th>Last Error</th>
                </tr>
                </thead>
                <tbody>
                <?php if ($integrations !== null) {
                    while ($row = mysqli_fetch_assoc($integrations)) {
                        $last_success = $row['integration_last_success_at'] ?: 'Never';
                        $last_error_at = $row['integration_last_error_at'] ?: '';
                        $last_error = $row['integration_last_error'] ?: '';
                        ?>
                        <tr>
                            <td>
                                <strong><?php echo nullable_htmlentities($row['integration_name']); ?></strong>
                                <div class="text-secondary">
                                    API <?php echo nullable_htmlentities($row['integration_api_version'] ?: 'not set'); ?>
                                </div>
                            </td>
                            <td><?php echo nullable_htmlentities($row['integration_provider']); ?></td>
                            <td><?php echo n45IntegrationStatusBadge((string) $row['integration_status']); ?></td>
                            <td><?php echo n45IntegrationStatusBadge((string) $row['integration_health_status']); ?></td>
                            <td><?php echo nullable_htmlentities($last_success); ?></td>
                            <td>
                                <?php if ($last_error_at || $last_error) { ?>
                                    <span class="text-danger"><?php echo nullable_htmlentities($last_error_at ?: 'Error'); ?></span>
                                    <div class="text-secondary"><?php echo nullable_htmlentities($last_error); ?></div>
                                <?php } else { ?>
                                    <span class="text-muted">None</span>
                                <?php } ?>
                            </td>
                        </tr>
                    <?php }
                } ?>
                </tbody>
            </table>
        </div>

        <?php if ($integration_tables_ready && (int) $num_rows[0] === 0) { ?>
            <div class="text-center text-muted py-4">
                <i class="fas fa-fw fa-plug fa-2x mb-3"></i>
                <p class="mb-0">No integrations have been configured yet.</p>
            </div>
        <?php } ?>

        <?php if ($integration_tables_ready) { require_once "../includes/filter_footer.php"; } ?>
    </div>
</div>

<div class="row">
    <div class="col-lg-6">
        <div class="card card-outline card-info">
            <div class="card-header">
                <h3 class="card-title"><i class="fas fa-fw fa-stream mr-2"></i>Recent Integration Events</h3>
            </div>
            <div class="card-body p-0">
                <table class="table table-sm table-borderless mb-0">
                    <tbody>
                    <?php foreach ($recent_events as $event) { ?>
                        <tr>
                            <td>
                                <strong><?php echo nullable_htmlentities($event['integration_event_title']); ?></strong>
                                <div class="text-secondary">
                                    <?php echo nullable_htmlentities($event['integration_name'] ?: $event['integration_provider']); ?>
                                    &middot;
                                    <?php echo nullable_htmlentities($event['integration_event_created_at']); ?>
                                </div>
                            </td>
                            <td class="text-right">
                                <?php echo n45IntegrationStatusBadge((string) $event['integration_event_status']); ?>
                            </td>
                        </tr>
                    <?php } ?>
                    <?php if (empty($recent_events)) { ?>
                        <tr>
                            <td class="text-center text-muted py-4">No integration events yet.</td>
                        </tr>
                    <?php } ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <div class="col-lg-6">
        <div class="card card-outline card-secondary">
            <div class="card-header">
                <h3 class="card-title"><i class="fas fa-fw fa-tasks mr-2"></i>Sync Queue</h3>
            </div>
            <div class="card-body">
                <p class="mb-2">
                    <strong><?php echo $queued_job_count; ?></strong> queued or running integration jobs.
                </p>
                <p class="text-muted mb-0">
                    Sync workers, retry handling, and dead-letter views will use the shared
                    <code>integration_jobs</code> table added by this foundation.
                </p>
            </div>
        </div>
    </div>
</div>

<?php

require_once "../includes/footer.php";
