(function () {
  function setPageMarker() {
    var path = window.location.pathname.replace(/\/+$/, '');
    var file = path.split('/').pop() || 'dashboard.php';
    document.body.dataset.n45Page = file.replace('.php', '') || 'index';
  }

  function setSidebarState(collapsed) {
    document.body.classList.toggle('n45-sidebar-collapsed', collapsed);
    try {
      window.localStorage.setItem('n45-sidebar-collapsed', collapsed ? '1' : '0');
    } catch (error) {
      return;
    }
  }

  function initSidebar() {
    var collapsed = false;
    try {
      collapsed = window.localStorage.getItem('n45-sidebar-collapsed') === '1';
    } catch (error) {
      collapsed = false;
    }

    document.body.classList.toggle('n45-sidebar-collapsed', collapsed);

    document.querySelectorAll('[data-n45-sidebar-toggle]').forEach(function (button) {
      button.addEventListener('click', function (event) {
        event.preventDefault();

        if (window.matchMedia('(max-width: 991.98px)').matches) {
          document.body.classList.toggle('n45-sidebar-open');
          return;
        }

        setSidebarState(!document.body.classList.contains('n45-sidebar-collapsed'));
      });
    });
  }

  function enhanceTables() {
    document.querySelectorAll('.n45-page table.table').forEach(function (table) {
      table.classList.add('n45-table');

      var parent = table.parentElement;
      if (parent && (parent.classList.contains('table-responsive') || parent.classList.contains('table-responsive-sm'))) {
        parent.classList.add('n45-table-wrap');
      }
    });
  }

  function enhanceForms() {
    document.querySelectorAll('.n45-page form').forEach(function (form) {
      if (!form.classList.contains('form-inline')) {
        form.classList.add('n45-form');
      }
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    setPageMarker();
    initSidebar();
    enhanceTables();
    enhanceForms();
  });
})();
