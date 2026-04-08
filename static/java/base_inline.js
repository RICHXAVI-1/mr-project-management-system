(function () {
            'use strict';

            /* Dynamic year */
            var yr = document.getElementById('fp-year');
            if (yr) yr.textContent = new Date().getFullYear();

            /* Floating scroll-to-top */
            var btn = document.getElementById('fp-scroll-top-btn');
            if (btn) {
                window.addEventListener('scroll', function () {
                    btn.classList.toggle('fp-visible', window.pageYOffset > 320);
                }, { passive: true });
                btn.addEventListener('click', function () {
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                });
            }

            /* Reveal animation (footer items) */
            if ('IntersectionObserver' in window) {
                var obs = new IntersectionObserver(function (entries) {
                    entries.forEach(function (e) {
                        if (e.isIntersecting) { e.target.classList.add('fp-visible'); obs.unobserve(e.target); }
                    });
                }, { threshold: 0.15 });
                document.querySelectorAll('.fp-reveal').forEach(function (el) { obs.observe(el); });
            } else {
                document.querySelectorAll('.fp-reveal').forEach(function (el) { el.classList.add('fp-visible'); });
            }

            /* Newsletter */
            var nlEmail = document.getElementById('fp-nl-email');
            var nlBtn = document.getElementById('fp-nl-submit');
            var nlStatus = document.getElementById('fp-nl-status');

            function showStatus(msg, type) {
                if (!nlStatus) return;
                nlStatus.textContent = msg;
                nlStatus.className = 'fp-nl-status fp-' + type;
                setTimeout(function () { nlStatus.textContent = ''; nlStatus.className = 'fp-nl-status'; }, 4000);
            }
            function isValidEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.trim()); }

            if (nlBtn && nlEmail) {
                nlBtn.addEventListener('click', function () {
                    var val = nlEmail.value.trim();
                    if (!val) { showStatus('Please enter your email address.', 'error'); nlEmail.focus(); return; }
                    if (!isValidEmail(val)) { showStatus('Please enter a valid email address.', 'error'); nlEmail.focus(); return; }
                    nlBtn.disabled = true;
                    nlBtn.innerHTML = '<i class="fa fa-spinner fa-spin"></i>';
                    setTimeout(function () {
                        nlBtn.disabled = false;
                        nlBtn.innerHTML = '<i class="fa fa-check"></i>';
                        showStatus('You have subscribed successfully!', 'success');
                        nlEmail.value = '';
                        setTimeout(function () { nlBtn.innerHTML = '<i class="fa fa-arrow-right"></i>'; }, 2500);
                    }, 1200);
                });
                nlEmail.addEventListener('keydown', function (e) { if (e.key === 'Enter') nlBtn.click(); });
            }
        })();
