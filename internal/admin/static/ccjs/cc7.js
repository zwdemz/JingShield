// 主机URL
var host_url = function() {
    var port = location.port;
    var host = location.hostname;
    if (port == "") {
        return "http://" + host;
    } else {
        return "http://" + host + ":" + port;
    }
}

// 从全局变量获取token和redirect
var token = window.token;
var redirect = window.redirect;

// 滑动验证相关变量
var slider = document.getElementById('slider');
var sliderTrack = document.getElementById('slider-track');
var captchaGap = document.getElementById('captcha-gap');
var verificationResult = document.getElementById('verification-result');
var sliderText = document.getElementById('slider-text');

// 缺口位置（随机生成）
var gapPosition = Math.random() * (sliderTrack.offsetWidth - 120) + 60;

// 验证成功的阈值（像素）
var threshold = 5;

// 是否正在拖动
var isDragging = false;

// 初始化验证界面
function initVerification() {
    // 设置缺口位置
    captchaGap.style.left = gapPosition + 'px';
    captchaGap.style.top = (Math.random() * (200 - 60)) + 'px';
    
    // 添加滑块事件监听
    slider.addEventListener('mousedown', startDrag);
    slider.addEventListener('touchstart', startDrag, { passive: true });
    
    document.addEventListener('mousemove', drag);
    document.addEventListener('touchmove', drag, { passive: false });
    
    document.addEventListener('mouseup', stopDrag);
    document.addEventListener('touchend', stopDrag);
}

// 开始拖动
function startDrag(e) {
    isDragging = true;
    slider.style.transition = 'none';
    sliderText.textContent = '释放验证';
}

// 拖动中
function drag(e) {
    if (!isDragging) return;
    
    e.preventDefault();
    
    // 获取鼠标或触摸位置
    var clientX;
    if (e.type === 'mousemove') {
        clientX = e.clientX;
    } else {
        clientX = e.touches[0].clientX;
    }
    
    // 计算滑块位置
    var sliderX = clientX - sliderTrack.getBoundingClientRect().left - slider.offsetWidth / 2;
    
    // 限制滑块在轨道内
    sliderX = Math.max(0, Math.min(sliderX, sliderTrack.offsetWidth - slider.offsetWidth));
    
    // 更新滑块位置
    slider.style.left = sliderX + 'px';
}

// 停止拖动
function stopDrag() {
    if (!isDragging) return;
    
    isDragging = false;
    slider.style.transition = 'transform 0.3s ease';
    
    // 获取滑块最终位置
    var sliderX = parseInt(slider.style.left) || 0;
    
    // 验证是否成功
    if (Math.abs(sliderX - gapPosition) <= threshold) {
        // 验证成功
        verificationResult.textContent = '验证成功，正在跳转...';
        verificationResult.style.color = '#52c41a';
        slider.style.backgroundColor = '#52c41a';
        sliderText.textContent = '验证成功';
        sliderText.style.color = '#52c41a';
        
        // 发送验证请求
        sendVerificationRequest(sliderX);
    } else {
        // 验证失败
        verificationResult.textContent = '验证失败，请重试';
        verificationResult.style.color = '#f5222d';
        
        // 重置滑块位置
        slider.style.left = '0px';
        sliderText.textContent = '请拖动滑块';
        sliderText.style.color = '#666';
        
        // 重新生成缺口位置
        setTimeout(function() {
            gapPosition = Math.random() * (sliderTrack.offsetWidth - 120) + 60;
            captchaGap.style.left = gapPosition + 'px';
            captchaGap.style.top = (Math.random() * (200 - 60)) + 'px';
            verificationResult.textContent = '';
        }, 1000);
    }
}

// 发送验证请求
function sendVerificationRequest(sliderX) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/ccpro/verify.php', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                // 解析响应
                var response = JSON.parse(xhr.responseText);
                if (response.status === 'success') {
                    // 验证成功，刷新页面
                    window.location.reload();
                } else {
                    // 验证失败
                    verificationResult.textContent = response.message || '验证失败，请重试';
                    verificationResult.style.color = '#f5222d';
                    
                    // 重置滑块位置
                    slider.style.left = '0px';
                    sliderText.textContent = '请拖动滑块';
                    sliderText.style.color = '#666';
                    
                    // 重新生成缺口位置
                    gapPosition = Math.random() * (sliderTrack.offsetWidth - 120) + 60;
                    captchaGap.style.left = gapPosition + 'px';
                    captchaGap.style.top = (Math.random() * (200 - 60)) + 'px';
                }
            } else {
                // 请求失败
                verificationResult.textContent = '验证请求失败，请重试';
                verificationResult.style.color = '#f5222d';
            }
        }
    };
    // 构建请求参数
    var params = 'action=verify_human&token=' + Math.random() + '&position=' + sliderX + '&gap_position=' + gapPosition;
    xhr.send(params);
}

// 初始化验证
window.onload = function() {
    initVerification();
};