// 导航栏交互逻辑
document.addEventListener('DOMContentLoaded', () => {
    const mobileBtn = document.querySelector('.layui-nav-mobile-btn');
    const navMenu = document.querySelector('.layui-nav');
    
    // 移动端导航菜单切换
    if (mobileBtn && navMenu) {
        mobileBtn.addEventListener('click', () => {
            const isExpanded = mobileBtn.getAttribute('aria-expanded') === 'true';
            mobileBtn.setAttribute('aria-expanded', !isExpanded);
            navMenu.classList.toggle('layui-nav-show');
        });

        window.addEventListener('resize', () => {
            if (window.innerWidth > 768) {
                navMenu.classList.remove('layui-nav-show');
                mobileBtn.setAttribute('aria-expanded', 'false');
            }
        });
    }

    // 根据当前URL设置导航项的激活状态
    const currentPath = window.location.pathname;
    const navLinks = navMenu.querySelectorAll('.layui-nav-item a');

    navLinks.forEach(link => {
        const linkPath = new URL(link.href).pathname;
        const parentLi = link.closest('.layui-nav-item');

        if (parentLi) {
            // 移除可能存在的 layui-this 类
            parentLi.classList.remove('layui-this');
            
            // 如果链接路径与当前路径完全匹配，则添加 layui-this
            if (linkPath === currentPath) {
                parentLi.classList.add('layui-this');
            }
        }
    });
});