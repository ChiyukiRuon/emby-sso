(() => {
    'use strict'
    const data = JSON.parse(document.getElementById('bootstrap').textContent)
    document.querySelectorAll('input[name="Csrf"]').forEach(input => {
        input.value = data.csrf
    })
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', () => {
            form.querySelector('button').disabled = true
        })
    })
    window.addEventListener('pageshow', event => {
        if (event.persisted) location.reload()
    })
})()
