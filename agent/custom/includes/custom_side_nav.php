<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/ui/n45_nav.php';

$groups = [
    [
        'title' => 'Custom',
        'items' => [
            ['label' => 'Custom', 'url' => 'index.php', 'icon' => 'circle', 'active' => ['index.php']],
        ],
    ],
];

$footer = '<a href="../' . n45_attr($config_start_page) . '">' . n45_icon('arrow-left') . '<span>Back to workspace</span></a>';

echo n45_sidebar('Custom', 'Extension workspace', '../' . $config_start_page, $groups, $footer);
?>
