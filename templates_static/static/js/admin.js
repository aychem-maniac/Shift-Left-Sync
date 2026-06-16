document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("form").forEach(function (form) {
    form.addEventListener("submit", function () {
      const button = form.querySelector("button[type='submit']");
      if (button) {
        button.disabled = true;
      }
    });
  });
});
