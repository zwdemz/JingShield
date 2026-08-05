// 点击验证JavaScript代码
document.addEventListener('DOMContentLoaded', function() {
    var targetNumberElement = document.getElementById('targetNumber');
    var verifyGrid = document.getElementById('verifyGrid');
    var verifyStatus = document.getElementById('verifyStatus');
    var targetNumber;
    var isVerifying = false;
    
    // 初始化验证界面
    initVerification();
    
    function initVerification() {
        // 生成1-9之间的随机目标数字
        targetNumber = Math.floor(Math.random() * 9) + 1;
        targetNumberElement.textContent = targetNumber;
        
        // 生成包含目标数字的随机数字数组
        var numbers = [];
        while (numbers.length < 12) {
            // 允许重复数字，确保能生成12个数字
            var num = Math.floor(Math.random() * 9) + 1;
            numbers.push(num);
        }
        // 确保至少有一个目标数字
        if (!numbers.includes(targetNumber)) {
            numbers[Math.floor(Math.random() * numbers.length)] = targetNumber;
        }
        
        // 打乱数字顺序
        shuffleArray(numbers);
        
        // 创建验证按钮网格
        verifyGrid.innerHTML = '';
        numbers.forEach(function(num) {
            var btn = document.createElement('button');
            btn.className = 'verify-btn';
            btn.textContent = num;
            btn.addEventListener('click', function() {
                handleNumberClick(num, btn);
            });
            verifyGrid.appendChild(btn);
        });
        
        verifyStatus.textContent = '';
    }
    
    function handleNumberClick(num, btn) {
        if (isVerifying) return;
        
        if (num === targetNumber) {
            // 点击正确
            btn.classList.add('correct');
            verifyStatus.textContent = '验证中...';
            verifyStatus.style.color = '#faad14';
            isVerifying = true;
            
            // 发送验证请求
            sendVerificationRequest();
        } else {
            // 点击错误
            btn.classList.add('wrong');
            verifyStatus.textContent = '选择错误，请重新验证';
            verifyStatus.style.color = '#f5222d';
            
            // 2秒后重置验证
            setTimeout(function() {
                initVerification();
            }, 2000);
        }
    }
    
    function sendVerificationRequest() {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/ccpro/verify.php', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                try {
                    var response = JSON.parse(xhr.responseText);
                    if (response.status === 'success') {
                        verifyStatus.textContent = '验证成功！';
                        verifyStatus.style.color = '#52c41a';
                        // 验证成功，刷新页面
                        setTimeout(function() {
                            window.location.reload();
                        }, 1000);
                    } else {
                        // 验证失败
                        verifyStatus.textContent = '验证失败，请重试';
                        verifyStatus.style.color = '#f5222d';
                        isVerifying = false;
                        // 2秒后重置验证
                        setTimeout(function() {
                            initVerification();
                        }, 2000);
                    }
                } catch (e) {
                    // JSON解析错误
                    verifyStatus.textContent = '验证失败，请重试';
                    verifyStatus.style.color = '#f5222d';
                    isVerifying = false;
                    // 2秒后重置验证
                    setTimeout(function() {
                        initVerification();
                    }, 2000);
                }
            }
        };
        xhr.send('action=verify_slide&token=' + Math.random());
    }
    
    // 打乱数组顺序的辅助函数
    function shuffleArray(array) {
        for (var i = array.length - 1; i > 0; i--) {
            var j = Math.floor(Math.random() * (i + 1));
            var temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }
});