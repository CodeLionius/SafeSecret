document.addEventListener('DOMContentLoaded', function () {
    // Theme Management
    const themeToggle = document.getElementById('theme-toggle');
    const setTheme = (theme) => {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        if (themeToggle) {
            themeToggle.innerHTML = theme === 'dark' ?
                '<svg class="icon"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>' :
                '<svg class="icon"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
        }
    };

    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme');
            setTheme(current === 'dark' ? 'light' : 'dark');
        });
    }
    setTheme(localStorage.getItem('theme') || 'dark');

    // PIN Input Logic
    const boxes = document.querySelectorAll('.pin-box');
    const pinField = document.getElementById('pin');
    if (boxes.length > 0 && pinField) {
        boxes.forEach((box, idx) => {
            box.addEventListener('input', function () {
                if (this.value.length === 1 && idx < boxes.length - 1) {
                    boxes[idx + 1].focus();
                }
                let pin = '';
                boxes.forEach(b => pin += b.value);
                pinField.value = pin;
            });
            box.addEventListener('keydown', function (e) {
                if (e.key === 'Backspace' && this.value === '' && idx > 0) {
                    boxes[idx - 1].focus();
                }
            });
        });
    }

    // Unified Clipboard Handler
    window.copyToClipboard = function (elementId, feedbackId) {
        const element = document.getElementById(elementId);
        const feedback = document.getElementById(feedbackId);
        if (!element) return;
        const text = element.value || element.textContent;

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => showFeedback(feedback));
        } else {
            // Fallback
            element.select();
            try {
                document.execCommand('copy');
                showFeedback(feedback);
            } catch (err) {
                console.error('Copy failed', err);
            }
        }
    };

    function showFeedback(el) {
        if (!el) return;
        el.style.display = 'inline';
        setTimeout(() => el.style.display = 'none', 2000);
    }

    // Event Delegation for Copy Buttons
    document.addEventListener('click', function (e) {
        if (e.target.matches('#copy-btn')) {
            const targetId = e.target.getAttribute('data-copy-target') || 'share-link';
            const feedbackId = e.target.getAttribute('data-copy-feedback') || 'link-feedback';
            copyToClipboard(targetId, feedbackId);
        }
    });

    // Font Size Management
    const setFontSize = (size) => {
        document.documentElement.style.setProperty('--font-size', size + 'rem');
        localStorage.setItem('fontSize', size);
    };
    const getFontSize = () => parseFloat(localStorage.getItem('fontSize')) || 1;

    const incBtn = document.getElementById('increase-font');
    const decBtn = document.getElementById('decrease-font');
    const resBtn = document.getElementById('reset-font');

    if (incBtn) incBtn.addEventListener('click', () => setFontSize(Math.min(getFontSize() + 0.1, 2)));
    if (decBtn) decBtn.addEventListener('click', () => setFontSize(Math.max(getFontSize() - 0.1, 0.7)));
    if (resBtn) resBtn.addEventListener('click', () => setFontSize(1));

    setFontSize(getFontSize());

    // File List Preview
    const fileInput = document.getElementById('fileInputFiles');
    const fileList = document.getElementById('fileList');
    if (fileInput && fileList) {
        fileInput.addEventListener('change', () => {
            fileList.innerHTML = '';
            Array.from(fileInput.files).forEach(file => {
                const div = document.createElement('div');
                div.className = 'mt-2 text-sm text-secondary flex items-center gap-2';
                div.innerHTML = `<svg class="icon w-4 h-4"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg> <span>${file.name}</span>`;
                fileList.appendChild(div);
            });
        });
    }
});
