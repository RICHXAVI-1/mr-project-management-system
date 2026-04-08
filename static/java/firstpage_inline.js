/* ── SERVICES FILTER & REVEAL JS ── */
		(function () {
			'use strict';

			/* Filter functionality */
			var filterBtns = document.querySelectorAll('.sv-filter-btn');
			var cards = document.querySelectorAll('.sv-cat-card');

			filterBtns.forEach(function (btn) {
				btn.addEventListener('click', function () {
					var filter = this.getAttribute('data-filter');

					/* Update active button */
					filterBtns.forEach(function (b) { b.classList.remove('sv-active'); });
					this.classList.add('sv-active');

					/* Show / hide cards */
					cards.forEach(function (card) {
						var cat = card.getAttribute('data-category');
						if (filter === 'all' || cat === filter) {
							card.classList.remove('sv-hidden');
						} else {
							card.classList.add('sv-hidden');
						}
					});
				});
			});

			/* Reveal observer */
			if ('IntersectionObserver' in window) {
				var obs = new IntersectionObserver(function (entries) {
					entries.forEach(function (e) {
						if (e.isIntersecting) { e.target.classList.add('sv-visible'); obs.unobserve(e.target); }
					});
				}, { threshold: 0.1 });
				document.querySelectorAll('.sv-reveal').forEach(function (el) { obs.observe(el); });
			} else {
				document.querySelectorAll('.sv-reveal').forEach(function (el) { el.classList.add('sv-visible'); });
			}
		})();

function showPTab(id, btn) {
				document.querySelectorAll('.p-tab-content').forEach(function (el) { el.classList.remove('active'); });
				document.querySelectorAll('.p-tab-btn').forEach(function (el) { el.classList.remove('active'); });
				document.getElementById('ptab-' + id).classList.add('active');
				btn.classList.add('active');
			}

/* ── ABOUT SECTION JS (auto-play + click + reveal) ── */
		(function () {
			'use strict';
			var mainImg = document.getElementById('ab-main-img');
			var thumbs = document.querySelectorAll('.ab-thumb');
			var imgWrap = document.querySelector('.ab-img-wrap');
			if (!mainImg || !thumbs.length) return;

			var current = 0;
			var autoTimer = null;
			var INTERVAL = 3500; /* ms between slides */

			/* Smooth fade transition on the main image */
			mainImg.style.transition = 'opacity 0.3s ease';

			/* Switch to a specific thumbnail index */
			function showSlide(idx) {
				idx = (idx + thumbs.length) % thumbs.length;
				current = idx;
				var src = thumbs[idx].getAttribute('data-img');
				mainImg.style.opacity = '0';
				setTimeout(function () {
					mainImg.src = src;
					mainImg.style.opacity = '1';
				}, 280);
				thumbs.forEach(function (t) { t.classList.remove('ab-thumb-active'); });
				thumbs[idx].classList.add('ab-thumb-active');
			}

			/* Auto-play */
			function startAuto() {
				stopAuto();
				autoTimer = setInterval(function () { showSlide(current + 1); }, INTERVAL);
			}
			function stopAuto() {
				if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
			}

			/* Manual click on thumbnails — restart auto after 6 s */
			thumbs.forEach(function (thumb, idx) {
				thumb.addEventListener('click', function () {
					stopAuto();
					showSlide(idx);
					setTimeout(startAuto, 6000);
				});
			});

			/* Pause auto-play while hovering the image */
			if (imgWrap) {
				imgWrap.addEventListener('mouseenter', stopAuto);
				imgWrap.addEventListener('mouseleave', startAuto);
			}

			/* Start auto-play */
			startAuto();

			/* Reveal observer */
			function runObserver(selector, visClass, threshold) {
				if (!('IntersectionObserver' in window)) {
					document.querySelectorAll(selector).forEach(function (el) { el.classList.add(visClass); });
					return;
				}
				var obs = new IntersectionObserver(function (entries) {
					entries.forEach(function (e) {
						if (e.isIntersecting) { e.target.classList.add(visClass); obs.unobserve(e.target); }
					});
				}, { threshold: threshold || 0.1 });
				document.querySelectorAll(selector).forEach(function (el) { obs.observe(el); });
			}
			runObserver('.ab-reveal-left', 'ab-visible', 0.1);
			runObserver('.ab-reveal-right', 'ab-visible', 0.1);
		})();

/* ── INTERSECTION OBSERVER (Services + Reviews) ── */
		(function () {
			'use strict';
			function runObserver(sel, vis, thr) {
				if (!('IntersectionObserver' in window)) {
					document.querySelectorAll(sel).forEach(function (el) { el.classList.add(vis); });
					return;
				}
				var obs = new IntersectionObserver(function (entries) {
					entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add(vis); obs.unobserve(e.target); } });
				}, { threshold: thr || 0.1 });
				document.querySelectorAll(sel).forEach(function (el) { obs.observe(el); });
			}
			runObserver('.sv-reveal', 'sv-visible', 0.1);
			runObserver('.rv-reveal', 'rv-visible', 0.1);
		})();

		/* ── REVIEWS SLIDER (responsive: 3-per-page desktop / 1-per-page mobile) ── */
		(function () {
			'use strict';
			var track = document.getElementById('rv-track');
			var prev = document.getElementById('rv-prev');
			var next = document.getElementById('rv-next');
			var dotsEl = document.getElementById('rv-dots');
			if (!track || !prev || !next) return;

			var MOBILE_BP = 760;
			var TOTAL_REAL = 5;   /* real review cards */
			var current = 0;
			var perPage, pages, dots, autoTimer;

			/* Build dot buttons */
			function buildDots() {
				dotsEl.innerHTML = '';
				dots = [];
				for (var i = 0; i < pages; i++) {
					var btn = document.createElement('button');
					btn.className = 'rv-dot' + (i === 0 ? ' rv-dot-active' : '');
					btn.setAttribute('aria-label', 'Slide ' + (i + 1));
					(function (idx) { btn.addEventListener('click', function () { stopAuto(); goTo(idx); startAuto(); }); })(i);
					dotsEl.appendChild(btn);
					dots.push(btn);
				}
			}

			/* Show/hide ghost card on desktop */
			function syncGhost() {
				var ghost = track.querySelector('.rv-ghost');
				if (ghost) ghost.style.display = perPage === 1 ? 'none' : '';
			}

			/* Initialise / re-initialise on resize */
			function init() {
				var isMobile = window.innerWidth <= MOBILE_BP;
				perPage = isMobile ? 1 : 3;
				pages = Math.ceil(TOTAL_REAL / perPage);
				if (current >= pages) current = pages - 1;
				buildDots();
				syncGhost();
				applyTransform(false); /* no animation on init */
			}

			function applyTransform(animate) {
				track.style.transition = animate
					? 'transform 0.55s cubic-bezier(.4,0,.2,1)'
					: 'none';
				track.style.transform = 'translateX(-' + (current * perPage * (100 / perPage)) + '%)';
			}

			function goTo(idx) {
				idx = (idx + pages) % pages;
				current = idx;
				track.style.transition = 'transform 0.55s cubic-bezier(.4,0,.2,1)';
				track.style.transform = 'translateX(-' + (current * 100) + '%)';
				dots.forEach(function (d, i) { d.classList.toggle('rv-dot-active', i === idx); });
			}

			function startAuto() { stopAuto(); autoTimer = setInterval(function () { goTo(current + 1); }, 5000); }
			function stopAuto() { if (autoTimer) { clearInterval(autoTimer); autoTimer = null; } }

			prev.addEventListener('click', function () { stopAuto(); goTo(current - 1); startAuto(); });
			next.addEventListener('click', function () { stopAuto(); goTo(current + 1); startAuto(); });

			/* Swipe */
			var touchX = 0;
			track.parentElement.addEventListener('touchstart', function (e) { touchX = e.touches[0].clientX; }, { passive: true });
			track.parentElement.addEventListener('touchend', function (e) {
				var diff = touchX - e.changedTouches[0].clientX;
				if (Math.abs(diff) > 40) { stopAuto(); goTo(diff > 0 ? current + 1 : current - 1); startAuto(); }
			}, { passive: true });

			/* Pause on hover */
			track.parentElement.addEventListener('mouseenter', stopAuto);
			track.parentElement.addEventListener('mouseleave', startAuto);

			/* Resize: re-init but debounced */
			var resizeTimer;
			window.addEventListener('resize', function () {
				clearTimeout(resizeTimer);
				resizeTimer = setTimeout(function () { stopAuto(); init(); startAuto(); }, 150);
			});

			init();
			startAuto();
		})();

/* ============================================================
		   MR. PROJECT — CONTACT/FOOTER JAVASCRIPT
		   Scoped, dependency-free vanilla JS
		   ============================================================ */
		(function () {
			'use strict';

			/* -- Dynamic copyright year -- */
			var yearEl = document.getElementById('fp-year');
			if (yearEl) yearEl.textContent = new Date().getFullYear();

			/* -- Floating scroll-to-top button -- */
			var scrollBtn = document.getElementById('fp-scroll-top-btn');
			if (scrollBtn) {
				var onScroll = function () {
					if (window.pageYOffset > 320) {
						scrollBtn.classList.add('fp-visible');
					} else {
						scrollBtn.classList.remove('fp-visible');
					}
				};
				window.addEventListener('scroll', onScroll, { passive: true });
				onScroll();

				scrollBtn.addEventListener('click', function () {
					window.scrollTo({ top: 0, behavior: 'smooth' });
				});
			}

			/* -- Intersection Observer: reveal animations -- */
			if ('IntersectionObserver' in window) {
				var observer = new IntersectionObserver(function (entries) {
					entries.forEach(function (entry) {
						if (entry.isIntersecting) {
							entry.target.classList.add('fp-visible');
							observer.unobserve(entry.target);
						}
					});
				}, { threshold: 0.15 });

				document.querySelectorAll('.fp-reveal').forEach(function (el) {
					observer.observe(el);
				});
			} else {
				/* Fallback for older browsers */
				document.querySelectorAll('.fp-reveal').forEach(function (el) {
					el.classList.add('fp-visible');
				});
			}

			/* -- Newsletter subscription handler -- */
			var nlEmail = document.getElementById('fp-nl-email');
			var nlBtn = document.getElementById('fp-nl-submit');
			var nlStatus = document.getElementById('fp-nl-status');

			function showStatus(msg, type) {
				if (!nlStatus) return;
				nlStatus.textContent = msg;
				nlStatus.className = 'fp-nl-status fp-' + type;
				setTimeout(function () {
					nlStatus.textContent = '';
					nlStatus.className = 'fp-nl-status';
				}, 4000);
			}

			function isValidEmail(email) {
				return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
			}

			if (nlBtn && nlEmail) {
				nlBtn.addEventListener('click', function () {
					var val = nlEmail.value.trim();
					if (!val) {
						showStatus('Please enter your email address.', 'error');
						nlEmail.focus();
						return;
					}
					if (!isValidEmail(val)) {
						showStatus('Please enter a valid email address.', 'error');
						nlEmail.focus();
						return;
					}
					/* Simulate subscription (replace with your real endpoint if needed) */
					nlBtn.disabled = true;
					nlBtn.innerHTML = '<i class="fa fa-spinner fa-spin"></i>';
					setTimeout(function () {
						nlBtn.disabled = false;
						nlBtn.innerHTML = '<i class="fa fa-check"></i>';
						showStatus('You have subscribed successfully!', 'success');
						nlEmail.value = '';
						setTimeout(function () {
							nlBtn.innerHTML = '<i class="fa fa-arrow-right"></i>';
						}, 2500);
					}, 1200);
				});

				nlEmail.addEventListener('keydown', function (e) {
					if (e.key === 'Enter') nlBtn.click();
				});
			}

		})();
