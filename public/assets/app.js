// DevTalk site-wide behaviour. Kept in an external file so the
// Content-Security-Policy can forbid inline scripts and event handlers.
(() => {
    'use strict';

    // <form data-confirm="Question?"> asks before submitting.
    document.addEventListener('submit', (event) => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement)) {
            return;
        }
        const question = form.dataset.confirm;
        if (question && !window.confirm(question)) {
            event.preventDefault();
        }
    });
})();
