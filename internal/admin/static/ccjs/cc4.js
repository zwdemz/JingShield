// JS跳转验证JavaScript代码
(function() {
    // 使用全局变量中的token和redirect参数
    var token = window.token || '';
    var redirect = window.redirect || '';
    
    // 延迟跳转，模拟验证过程
    setTimeout(function() {
        // 构造验证URL
        var verifyUrl = '/ccpro/verify.php?action=verify_jsredirect&token=' + token + '&redirect=' + encodeURIComponent(redirect);
        
        // 跳转到验证页面
        window.location.href = verifyUrl;
    }, 2000);
})();