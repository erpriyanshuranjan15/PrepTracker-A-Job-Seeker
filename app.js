function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

document.addEventListener('click', function(e) {
  const sidebar = document.getElementById('sidebar');
  const menuBtn = document.querySelector('.menu-btn');
  if (window.innerWidth <= 768 && sidebar && menuBtn && !sidebar.contains(e.target) && e.target !== menuBtn) {
    sidebar.classList.remove('open');
  }
});

window.addEventListener('load', () => {
  const fills = document.querySelectorAll('.skill-bar-fill');
  fills.forEach(f => {
    const target = f.style.width;
    f.style.width = '0%';
    requestAnimationFrame(() => {
      setTimeout(() => { f.style.width = target; }, 100);
    });
  });
});
