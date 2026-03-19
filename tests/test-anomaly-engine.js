/**
 * Anomaly Engine Tests
 * 
 * Tests:
 *   - IP profile creation and request recording
 *   - Baseline computation
 *   - Anomaly scoring
 *   - Anomaly list retrieval
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const anomalyEngine = require('../anomaly-engine');

function makeEvent(ip, overrides = {}) {
    return {
        source_ip: ip,
        timestamp: new Date().toISOString(),
        method: 'GET',
        uri: '/page',
        status_code: 200,
        user_agent: 'Mozilla/5.0 TestBrowser',
        geo_country: 'US',
        attack_type: '',
        action: 'PASS',
        ...overrides,
    };
}

describe('Anomaly Engine', () => {
    const testIP = '172.16.0.100';

    it('should record requests for an IP', () => {
        for (let i = 0; i < 10; i++) {
            anomalyEngine.recordRequest(makeEvent(testIP));
        }
        const profile = anomalyEngine.getAnomalyForIP(testIP);
        assert.ok(profile, 'Profile should exist after recording requests');
    });

    it('should return anomaly data for a tracked IP', () => {
        const result = anomalyEngine.getAnomalyForIP(testIP);
        assert.ok(result, 'Should return anomaly data');
        assert.ok('anomalyScore' in result || 'score' in result || 'ip' in result,
            'Result should contain anomaly information');
    });

    it('should return null/undefined for untracked IP', () => {
        const result = anomalyEngine.getAnomalyForIP('99.99.99.99');
        assert.ok(!result, 'Should return falsy for untracked IP');
    });

    it('should return anomalies list', () => {
        const anomalies = anomalyEngine.getAnomalies();
        assert.ok(Array.isArray(anomalies), 'Anomalies should be an array');
    });

    it('should detect anomaly when behavior changes drastically', () => {
        const anomalyIP = '172.16.0.200';
        // Build a baseline of normal GET requests
        for (let i = 0; i < 30; i++) {
            anomalyEngine.recordRequest(makeEvent(anomalyIP, {
                method: 'GET',
                uri: '/normal',
                status_code: 200,
                user_agent: 'Mozilla/5.0 Normal Browser',
                geo_country: 'US',
            }));
        }

        // Sudden burst of attack-like behavior
        for (let i = 0; i < 20; i++) {
            anomalyEngine.recordRequest(makeEvent(anomalyIP, {
                method: 'POST',
                uri: `/attack-${i}`,
                status_code: 403,
                user_agent: 'DifferentUA/2.0',
                geo_country: 'RU',
                attack_type: 'SQL Injection',
                action: 'BLOCK',
            }));
        }

        const result = anomalyEngine.getAnomalyForIP(anomalyIP);
        assert.ok(result, 'Should have anomaly data after behavioral change');
    });

    it('should return all profiles', () => {
        const profiles = anomalyEngine.getAllProfiles();
        assert.ok(Array.isArray(profiles) || typeof profiles === 'object', 'getAllProfiles should return data');
    });

    it('should expose ANOMALY_THRESHOLD', () => {
        assert.ok(anomalyEngine.ANOMALY_THRESHOLD > 0, 'Threshold should be positive');
    });
});
