(function() {
    // 1. Initialize honeypots
    const initHoneypots = () => {
        document.querySelectorAll('form').forEach(form => {
            const hp = document.createElement('input');
            hp.type = 'text';
            hp.name = 'honeypot_field';
            hp.style.cssText = 'position:absolute;left:-9999px;opacity:0';
            form.appendChild(hp);
        });
    };

    // 2. Generate device fingerprint
    const getFingerprint = () => {
        return btoa(JSON.stringify({
            t: Date.now(),
            u: navigator.userAgent,
            r: Math.random().toString(36).slice(2),
            s: `${screen.width}x${screen.height}`
        })).replace(/=/g, '');
    };

    // 3. Form protection
    const protectForms = () => {
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function(e) {
                // Validate honeypot
                if (this.querySelector('[name="honeypot_field"]').value) {
                    e.preventDefault();
                    return false;
                }

                // Add fingerprint token
                const token = document.createElement('input');
                token.type = 'hidden';
                token.name = 'js_token';
                token.value = getFingerprint();
                this.appendChild(token);
            });
        });
    };

    // Initialize
    document.addEventListener('DOMContentLoaded', () => {
        initHoneypots();
        protectForms();
        localStorage.setItem('bot_token', getFingerprint());
    });
})();