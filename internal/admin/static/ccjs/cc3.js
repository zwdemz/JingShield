// 点击验证JavaScript代码
var clickBtn = document.getElementById('clickBtn');

clickBtn.addEventListener('click', function() {
    // 禁用按钮防止重复点击
    clickBtn.disabled = true;
    clickBtn.textContent = '验证中...';
    
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
                // 验证失败，恢复按钮
                clickBtn.disabled = false;
                clickBtn.textContent = '点击验证';
                alert('验证失败，请重试');
            }
        }
    };
    xhr.send('action=verify_click&token=' + Math.random());
});