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
// ── 회원가입 클라이언트 검증 ──────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
    var form = document.getElementById('reg-form');
    if (!form) return;

    form.addEventListener('submit', function(e) {
        var username = form.querySelector('[name=username]').value.trim();
        var email    = form.querySelector('[name=email]').value.trim();
        var password = form.querySelector('[name=password]').value;
        var errors   = [];

        if (username.length < 3 || username.length > 20)
            errors.push('아이디는 3~20자 사이여야 합니다');
        if (!/^[a-zA-Z0-9_]+$/.test(username))
            errors.push('아이디는 영문·숫자·밑줄(_)만 사용 가능합니다');
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
            errors.push('올바른 이메일 형식이 아닙니다');
        if (password.length < 8)
            errors.push('비밀번호는 8자 이상이어야 합니다');
        if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password))
            errors.push('비밀번호는 영문과 숫자를 모두 포함해야 합니다');

        if (errors.length > 0) {
            e.preventDefault();
            var box = document.getElementById('reg-error-box');
            if (!box) {
                box = document.createElement('div');
                box.id = 'reg-error-box';
                box.className = 'error-box';
                box.style.marginBottom = '12px';
                form.insertBefore(box, form.firstChild);
            }
            box.innerHTML = errors.join('<br>');
        }
    });
});
