function closeModal(id) {
    document.getElementById(id).style.display = 'none';
}

function formatTime(val) {
    if (!val) return '';
    const d = new Date(val);
    if (isNaN(d.getTime())) return val;
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const h = String(d.getHours()).padStart(2, '0');
    const min = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${day} ${h}:${min}:${s}`;
}

window.onclick = function(e) {
    document.querySelectorAll('.modal').forEach(m => {
        if (e.target === m) m.style.display = 'none';
    });
}
