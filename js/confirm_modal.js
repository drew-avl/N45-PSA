$(document).ready(function() {
  $("a.confirm-link, button.confirm-link, input.confirm-link").click(function(e) {
      e.preventDefault();

      var element = this;

      // Show the confirmation modal
      $("#confirmationModal").modal('show');

      // When the submission is confirmed via the modal
      $("#confirmSubmitBtn").off('click').on('click', function() {
          if ($(element).is('a')) {
              window.location.href = $(element).attr('href');
          } else {
              var form = $();
              var formId = $(element).attr('form');
              if (formId) {
                  form = $('#' + formId);
              }
              if (!form.length) {
                  form = $(element).closest('form');
              }
              if (form.length) {
                  form.submit();
              }
          }
      });
  });
});
