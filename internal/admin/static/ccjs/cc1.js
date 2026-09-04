// 5秒盾验证JavaScript代码
var countdown = 5;
var countdownEl = document.getElementById('countdown');
var verifyBtn = document.getElementById('verifyBtn');

var timer = setInterval(function() {
    countdown--;
    countdownEl.textContent = countdown;
    
    if (countdown <= 0) {
        clearInterval(timer);
        verifyBtn.disabled = false;
        verifyBtn.textContent = '立即验证';
    }
}, 1000);

verifyBtn.addEventListener('click', function() {
    // 发送验证请求
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/ccpro/verify.php', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            var response = JSON.parse(xhr.responseText);
            if (response.status === 'success') {
                // 验证成功，刷新页面
                window.location.reload();
            } else {
                // 验证失败，提示用户
                alert('验证失败，请重试');
            }
        }
    };
    xhr.send('action=verify_5second&token=' + Math.random());
});