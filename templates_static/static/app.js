function showTab(t) {
    const tabs = document.querySelectorAll('.tab-button');
    const panes = document.querySelectorAll('.tab-pane');

    tabs.forEach(tab => tab.classList.remove('active'));
    panes.forEach(pane => pane.classList.remove('active'));

    if (t === 'login') {
        document.getElementById('tab-login').classList.add('active');
        document.getElementById('pane-login').classList.add('active');
    } else if (t === 'reg') {
        document.getElementById('tab-reg').classList.add('active');
        document.getElementById('pane-reg').classList.add('active');
    }
}