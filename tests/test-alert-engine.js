/**
 * Alert Engine Tests
 * 
 * Tests:
 *   - Alert creation
 *   - Cooldown deduplication
 *   - Critical attack alert generation
 *   - Alert retrieval and limits
 *   - Mark read / unread count
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const alertEngine = require('../alert-engine');

describe('Alert Engine', () => {
    describe('Alert Creation', () => {
        it('should create an alert via addAlert', () => {
            const alert = alertEngine.addAlert(
                'test', 'HIGH', 'Test Alert', 'This is a test alert', { key: 'value' }
            );
            assert.ok(alert, 'Alert should be created');
            assert.ok(alert.id, 'Alert should have an ID');
            assert.strictEqual(alert.type, 'test');
            assert.strictEqual(alert.severity, 'HIGH');
            assert.strictEqual(alert.title, 'Test Alert');
            assert.strictEqual(alert.read, false, 'New alert should be unread');
        });

        it('should deduplicate alerts within cooldown window', () => {
            // Same type+title within 5 minutes should be suppressed
            const alert1 = alertEngine.addAlert(
                'dedup-test', 'MEDIUM', 'Duplicate Alert', 'First'
            );
            const alert2 = alertEngine.addAlert(
                'dedup-test', 'MEDIUM', 'Duplicate Alert', 'Second'
            );
            // alert2 should be undefined (suppressed by cooldown)
            assert.ok(alert1, 'First alert should be created');
            assert.strictEqual(alert2, undefined, 'Duplicate alert should be suppressed by cooldown');
        });
    });

    describe('Event Recording', () => {
        it('should generate alert for critical blocked attacks', () => {
            const initialCount = alertEngine.getAlerts(1000).length;
            alertEngine.recordEvent({
                source_ip: '10.0.0.99',
                severity: 'CRITICAL',
                action: 'BLOCK',
                attack_type: 'SQL Injection',
                uri: '/test-critical',
                rule_id: '942100',
                rule_msg: 'SQL Injection Attack Detected',
            });
            const alerts = alertEngine.getAlerts(1000);
            assert.ok(alerts.length > initialCount, 'Should have generated a new alert');
            const criticalAlert = alerts.find(a => a.type === 'attack' && a.severity === 'CRITICAL');
            assert.ok(criticalAlert, 'Should have a critical attack alert');
        });

        it('should not generate alert for non-critical events', () => {
            const countBefore = alertEngine.getAlerts(1000).length;
            alertEngine.recordEvent({
                source_ip: '10.0.0.100',
                severity: 'INFO',
                action: 'PASS',
                attack_type: '',
                uri: '/normal',
                rule_id: '',
                rule_msg: '',
            });
            const countAfter = alertEngine.getAlerts(1000).length;
            // INFO/PASS events should not generate alerts
            assert.strictEqual(countAfter, countBefore, 'INFO event should not generate alert');
        });
    });

    describe('Alert Management', () => {
        it('should return alerts with limit', () => {
            const alerts = alertEngine.getAlerts(5);
            assert.ok(Array.isArray(alerts), 'Alerts should be an array');
            assert.ok(alerts.length <= 5, 'Should respect limit');
        });

        it('should return unread count', () => {
            const count = alertEngine.getUnreadCount();
            assert.ok(typeof count === 'number', 'Unread count should be a number');
            assert.ok(count >= 0, 'Count should be non-negative');
        });

        it('should mark a single alert as read', () => {
            const alerts = alertEngine.getAlerts(1);
            if (alerts.length > 0 && !alerts[0].read) {
                alertEngine.markRead(alerts[0].id);
                const updated = alertEngine.getAlerts(1000);
                const alert = updated.find(a => a.id === alerts[0].id);
                assert.strictEqual(alert.read, true, 'Alert should be marked as read');
            }
        });

        it('should mark all alerts as read', () => {
            alertEngine.markAllRead();
            const count = alertEngine.getUnreadCount();
            assert.strictEqual(count, 0, 'All alerts should be read after markAllRead');
        });
    });
});
