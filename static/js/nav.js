// 导航栏交互逻辑
document.addEventListener('DOMContentLoaded', () => {
    const mobileBtn = document.querySelector('.layui-nav-mobile-btn');
    const navMenu = document.querySelector('.layui-nav');
    
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
});