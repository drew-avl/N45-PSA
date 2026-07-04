(function () {
  function enhance(selector, className) {
    document.querySelectorAll(selector).forEach(function (element) {
      element.classList.add(className);
    });
  }

  function setPageMarker() {
    var path = window.location.pathname.replace(/\/+$/, '');
    var file = path.split('/').pop() || 'dashboard.php';
    document.body.dataset.n45Page = file.replace('.php', '');
  }

  function enhanceTables() {
    document.querySelectorAll('.content-wrapper table.table').forEach(function (table) {
      table.classList.add('n45-table');

      var parent = table.parentElement;
      if (parent && parent.classList.contains('table-responsive')) {
        parent.classList.add('n45-table-shell');
      }
    });
  }

  function enhanceFilters() {
    document.querySelectorAll('.content-wrapper form').forEach(function (form) {
      if (form.querySelector('input[type="search"], [data-target="#advancedFilter"], #advancedFilter')) {
        form.classList.add('n45-filter-form');
      }
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    setPageMarker();
    enhance('.content-wrapper .card', 'n45-panel');
    enhance('.content-wrapper .small-box', 'n45-metric');
    enhanceTables();
    enhanceFilters();
  });
})();
