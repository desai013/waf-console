/**
 * WAF Behavior Tracker — Injected into proxied pages
 * =====================================================
 * Tracks mouse, keyboard, scroll, click, and touch patterns.
 * Reports entropy data back to the WAF for bot detection scoring.
 * 
 * This script is non-intrusive, lightweight (~2KB minified),
 * and designed to have zero visual impact on the proxied page.
 */
(function () {
    'use strict';
    if (window.__waf_behavior_loaded) return;
    window.__waf_behavior_loaded = true;

    var data = {
        mouse: { events: 0, lastX: 0, lastY: 0, distance: 0 },
        keyboard: { events: 0 },
        scroll: { events: 0, depth: 0 },
        clicks: { count: 0 },
        touch: { events: 0 }
    };
    var reportInterval = 10000; // Report every 10s
    var startTime = Date.now();

    // Mouse movement tracking — compute total distance
    document.addEventListener('mousemove', function (e) {
        data.mouse.events++;
        if (data.mouse.lastX > 0 || data.mouse.lastY > 0) {
            var dx = e.clientX - data.mouse.lastX;
            var dy = e.clientY - data.mouse.lastY;
            data.mouse.distance += Math.sqrt(dx * dx + dy * dy);
        }
        data.mouse.lastX = e.clientX;
        data.mouse.lastY = e.clientY;
    }, { passive: true });

    // Keyboard tracking — count keypresses (no actual keys recorded for privacy)
    document.addEventListener('keydown', function () {
        data.keyboard.events++;
    }, { passive: true });

    // Scroll depth tracking
    window.addEventListener('scroll', function () {
        data.scroll.events++;
        var scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        var docHeight = Math.max(
            document.body.scrollHeight, document.documentElement.scrollHeight,
            document.body.offsetHeight, document.documentElement.offsetHeight
        );
        var winHeight = window.innerHeight;
        var scrollPercent = Math.round((scrollTop / Math.max(1, docHeight - winHeight)) * 100);
        data.scroll.depth = Math.max(data.scroll.depth, scrollPercent);
    }, { passive: true });

    // Click tracking — count and timing
    document.addEventListener('click', function () {
        data.clicks.count++;
    }, { passive: true });

    // Touch tracking for mobile
    document.addEventListener('touchstart', function () {
        data.touch.events++;
    }, { passive: true });

    // Report behavior data to WAF endpoint
    function report() {
        if (data.mouse.events === 0 && data.keyboard.events === 0 &&
            data.scroll.events === 0 && data.clicks.count === 0 &&
            data.touch.events === 0) return; // Nothing to report

        var payload = {
            mouse: { events: data.mouse.events, distance: Math.round(data.mouse.distance) },
            keyboard: { events: data.keyboard.events },
            scroll: { events: data.scroll.events, depth: data.scroll.depth },
            clicks: { count: data.clicks.count },
            touch: { events: data.touch.events },
            pageView: true,
            sessionDuration: Date.now() - startTime
        };

        try {
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/__waf_behavior', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify(payload));
        } catch (e) { /* silent */ }

        // Reset counters (keep cumulative distance)
        data.mouse.events = 0;
        data.mouse.distance = 0;
        data.keyboard.events = 0;
        data.scroll.events = 0;
        data.clicks.count = 0;
        data.touch.events = 0;
    }

    // Report on interval
    setInterval(report, reportInterval);

    // Report on page unload
    window.addEventListener('beforeunload', report);

    // Initial page view report after 2s
    setTimeout(function () {
        try {
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/__waf_behavior', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify({ pageView: true, sessionDuration: Date.now() - startTime }));
        } catch (e) { /* silent */ }
    }, 2000);
})();
