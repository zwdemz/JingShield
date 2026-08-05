// 旋转验证JavaScript代码
(function() {
    var rotateImage = document.getElementById('rotateImage');
    var rotateLeftBtn = document.getElementById('rotateLeft');
    var rotateRightBtn = document.getElementById('rotateRight');
    var rotateAngleEl = document.getElementById('rotateAngle');
    var confirmBtn = document.getElementById('confirmBtn');
    
    var currentAngle = 0;
    var targetAngle = Math.floor(Math.random() * 4) * 90; // 0°, 90°, 180°, 270°
    
    // 初始化图片旋转
    function initRotation() {
        // 随机旋转图片到目标角度
        rotateImage.style.transform = 'rotate(' + targetAngle + 'deg)';
        currentAngle = targetAngle;
        updateAngleDisplay();
    }
    
    // 更新角度显示
    function updateAngleDisplay() {
        rotateAngleEl.textContent = currentAngle % 360 + '°';
    }
    
    // 向左旋转（逆时针）
    function rotateLeft() {
        currentAngle -= 90;
        if (currentAngle < 0) currentAngle += 360;
        rotateImage.style.transform = 'rotate(' + currentAngle + 'deg)';
        updateAngleDisplay();
    }
    
    // 向右旋转（顺时针）
    function rotateRight() {
        currentAngle += 90;
        if (currentAngle >= 360) currentAngle -= 360;
        rotateImage.style.transform = 'rotate(' + currentAngle + 'deg)';
        updateAngleDisplay();
    }
    
    // 发送验证请求
    function sendVerification() {
        // 检查旋转角度是否正确（允许±5°的误差）
        var isCorrect = Math.abs(currentAngle % 360) < 5 || Math.abs(currentAngle % 360 - 360) < 5;
        
        // 发送验证请求
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/ccpro/verify.php', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                var response = JSON.parse(xhr.responseText);
                if (response.status === 'success' && isCorrect) {
                    // 验证成功，刷新页面
                    window.location.reload();
                } else {
                    // 验证失败，提示用户
                    alert('验证失败，请确保图片已旋转到正确方向后重试');
                }
            }
        };
        xhr.send('action=verify_rotate&token=' + Math.random() + '&angle=' + currentAngle);
    }
    
    // 添加事件监听器
    rotateLeftBtn.addEventListener('click', rotateLeft);
    rotateRightBtn.addEventListener('click', rotateRight);
    confirmBtn.addEventListener('click', sendVerification);
    
    // 初始化验证
    initRotation();
})();