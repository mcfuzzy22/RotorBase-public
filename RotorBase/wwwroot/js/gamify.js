window.gamify = {
  toast: (text) => {
    const div = document.createElement('div');
    div.textContent = text;
    div.className = 'fixed left-1/2 top-4 z-[9999] -translate-x-1/2 rounded-lg bg-white/90 px-4 py-2 text-sm shadow ring-1 ring-black/5';
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 2200);
  },
  confetti: () => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:9998';
    document.body.appendChild(canvas);
    const ctx = canvas.getContext('2d');
    let width, height, tick = 0;
    const rand = () => (Math.random() * 2 - 1);
    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize, { passive: true });

    const parts = Array.from({ length: 120 }, () => ({
      x: width / 2,
      y: 60 + Math.random() * 40,
      vx: rand() * 4,
      vy: Math.random() * 2,
      size: 2 + Math.random() * 3,
      rotation: Math.random() * Math.PI * 2,
      hue: Math.floor(Math.random() * 360)
    }));

    const step = () => {
      tick++;
      ctx.clearRect(0, 0, width, height);
      parts.forEach((p) => {
        p.x += p.vx;
        p.y += (p.vy += 0.08);
        p.rotation += 0.1;
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rotation);
        ctx.fillStyle = `hsl(${p.hue} 80% 60%)`;
        ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size);
        ctx.restore();
      });

      if (tick < 120) {
        requestAnimationFrame(step);
      } else {
        window.removeEventListener('resize', resize);
        canvas.remove();
      }
    };

    requestAnimationFrame(step);
  }
};
