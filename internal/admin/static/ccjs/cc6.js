// 安全检测防护模式JavaScript代码
(function() {
    var progressFill = document.getElementById('progressFill');
    var progressText = document.getElementById('progressText');
    var securityResult = document.getElementById('securityResult');
    var actionBtn = document.getElementById('actionBtn');
    
    var checks = [
        { id: 'check1', text: '浏览器环境检测...' },
        { id: 'check2', text: '设备指纹验证...' },
        { id: 'check3', text: '网络环境安全检测...' },
        { id: 'check4', text: '行为模式分析...' },
        { id: 'check5', text: '恶意软件扫描...' }
    ];
    
    var currentCheck = 0;
    var totalChecks = checks.length;
    
    // 模拟安全检测
    function startSecurityChecks() {
        var timer = setInterval(function() {
            if (currentCheck < totalChecks) {
                performCheck(checks[currentCheck]);
                currentCheck++;
            } else {
                clearInterval(timer);
                completeSecurityChecks();
            }
        }, 800);
    }
    
    // 执行单个检测项目
    function performCheck(check) {
        var checkElement = document.getElementById(check.id);
        var checkTextElement = checkElement.nextElementSibling;
        
        // 更新检测文本
        checkTextElement.textContent = check.text;
        
        // 模拟检测过程
        setTimeout(function() {
            // 随机决定检测结果（实际应用中应根据真实检测逻辑判断）
            var isSuccess = Math.random() > 0.1; // 90%成功率
            
            if (isSuccess) {
                checkElement.className = 'check-icon success';
                checkElement.textContent = '✓';
                checkTextElement.textContent = check.text.replace('...', '完成');
            } else {
                checkElement.className = 'check-icon error';
                checkElement.textContent = '✗';
                checkTextElement.textContent = check.text.replace('...', '失败');
            }
            
            // 更新进度条
            updateProgress();
        }, 500);
    }
    
    // 更新进度条
    function updateProgress() {
        var progress = Math.min(100, Math.round((currentCheck / totalChecks) * 100));
        progressFill.style.width = progress + '%';
        progressText.textContent = progress + '% 检测中...';
    }
    
    // 完成所有安全检测
    function completeSecurityChecks() {
        progressText.textContent = '100% 检测完成';
        
        // 模拟验证结果（实际应用中应根据服务器返回结果判断）
        var isVerified = Math.random() > 0.15; // 85%验证成功率
        
        if (isVerified) {
            securityResult.className = 'security-result success';
            securityResult.innerHTML = '<strong>安全检测通过</strong><br>您的设备和浏览器环境安全，点击下方按钮完成验证。';
            actionBtn.style.display = 'block';
        } else {
            securityResult.className = 'security-result error';
            securityResult.innerHTML = '<strong>安全检测未通过</strong><br>您的设备或浏览器环境存在安全风险，请稍后重试。';
        }
    }
    
    // 收集浏览器和设备信息
    function collectBrowserInfo() {
        return {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            screen: screen.width + 'x' + screen.height,
            colorDepth: screen.colorDepth,
            timeZone: new Date().getTimezoneOffset(),
            javaEnabled: navigator.javaEnabled(),
            cookiesEnabled: navigator.cookieEnabled,
            plugins: Array.from(navigator.plugins).map(p => p.name).join(', ')
        };
    }
    
    // 发送验证请求
    function sendVerification() {
        var browserInfo = collectBrowserInfo();
        
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
                    alert('验证失败，请稍后重试');
                }
            }
        };
        
        // 构建请求参数
        var params = 'action=verify_securitycheck&token=' + Math.random();
        for (var key in browserInfo) {
            params += '&' + key + '=' + encodeURIComponent(browserInfo[key]);
        }
        
        xhr.send(params);
    }
    
    // 添加事件监听器
    actionBtn.addEventListener('click', sendVerification);
    
    // 启动安全检测
    startSecurityChecks();
})();