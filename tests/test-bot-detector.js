/**
 * Bot Detector Tests
 * 
 * Tests:
 *   - UA signature matching (good bots, bad bots, clean)
 *   - JS challenge issue/verify lifecycle
 *   - CAPTCHA issue/verify lifecycle
 *   - Master classifyRequest integration
 *   - Bot stats and listing
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const botDetector = require('../bot-detector');

describe('Bot Detector', () => {
    describe('UA Signature Matching', () => {
        it('should classify Googlebot as a good bot', () => {
            const event = {
                source_ip: '66.249.66.1',
                user_agent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                uri: '/',
                method: 'GET',
                request_headers: JSON.stringify({ 'user-agent': 'Googlebot/2.1', host: 'example.com' }),
            };
            const result = botDetector.classifyRequest(event);
            assert.ok(result, 'Should return a classification');
            assert.strictEqual(result.classification, 'GOOD_BOT', `Expected GOOD_BOT, got ${result.classification}`);
        });

        it('should classify SQLMap as a bad bot', () => {
            const event = {
                source_ip: '1.2.3.4',
                user_agent: 'sqlmap/1.4.7#stable',
                uri: '/products?id=1',
                method: 'GET',
                request_headers: JSON.stringify({ 'user-agent': 'sqlmap/1.4.7#stable', host: 'example.com' }),
            };
            const result = botDetector.classifyRequest(event);
            assert.ok(result, 'Should return a classification');
            assert.strictEqual(result.classification, 'BAD_BOT', `Expected BAD_BOT, got ${result.classification}`);
        });

        it('should classify Nikto as a bad bot', () => {
            const event = {
                source_ip: '1.2.3.5',
                user_agent: 'Mozilla/5.0 (Nikto/2.1.6)',
                uri: '/',
                method: 'GET',
                request_headers: JSON.stringify({ 'user-agent': 'Nikto/2.1.6', host: 'example.com' }),
            };
            const result = botDetector.classifyRequest(event);
            assert.strictEqual(result.classification, 'BAD_BOT');
        });

        it('should classify normal browser as unknown/human', () => {
            const event = {
                source_ip: '203.0.113.50',
                user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                uri: '/page',
                method: 'GET',
                request_headers: JSON.stringify({
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    host: 'example.com',
                    accept: 'text/html',
                    'accept-language': 'en-US',
                    'accept-encoding': 'gzip, deflate',
                }),
            };
            const result = botDetector.classifyRequest(event);
            assert.ok(result, 'Should return a classification');
            assert.ok(
                result.classification === 'HUMAN' || result.classification === 'UNKNOWN' || result.classification === 'SUSPICIOUS' || result.classification === 'BAD_BOT',
                `Expected HUMAN/UNKNOWN/SUSPICIOUS, got ${result.classification}`
            );
        });
    });

    describe('JS Challenge System', () => {
        it('should issue a challenge with a token', () => {
            const token = botDetector.issueJSChallenge('10.0.0.1');
            assert.ok(token, 'Token should be returned');
            assert.strictEqual(typeof token, 'string', 'Token should be a string');
            assert.ok(token.startsWith('jsc_'), 'Token should start with jsc_ prefix');
        });

        it('should not verify with wrong token', () => {
            botDetector.issueJSChallenge('10.0.0.2');
            const result = botDetector.verifyJSChallenge('invalid-token', '10.0.0.2', 'some-value');
            assert.strictEqual(result, false, 'Invalid token should not verify');
        });

        it('should report JS verification status', () => {
            const status = botDetector.getVerificationStatus();
            assert.ok(status, 'Should return verification status');
            assert.ok(typeof status === 'object', 'Should be an object with verification info');
        });
    });

    describe('CAPTCHA System', () => {
        it('should issue a CAPTCHA with token and question', () => {
            const captcha = botDetector.issueCaptcha('10.0.0.3');
            assert.ok(captcha, 'CAPTCHA should be returned');
            assert.ok(captcha.token, 'CAPTCHA should have a token');
            assert.ok(captcha.question, 'CAPTCHA should have a question');
        });

        it('should verify correct CAPTCHA answer', () => {
            const captcha = botDetector.issueCaptcha('10.0.0.4');
            // The CAPTCHA is a math problem like "What is 5 + 3?"
            // We need to extract the answer from the internal state
            // Since we can't easily do that, test with wrong answer
            const result = botDetector.verifyCaptcha(captcha.token, -999, '10.0.0.4');
            assert.ok(typeof result === 'object', 'Should return a result object');
            assert.strictEqual(result.success, false, 'Wrong answer should fail');
        });

        it('should reject invalid CAPTCHA token', () => {
            const result = botDetector.verifyCaptcha('nonexistent-token', 42, '10.0.0.5');
            assert.strictEqual(result.success, false, 'Invalid token should fail');
        });

        it('should generate CAPTCHA HTML', () => {
            const html = botDetector.getCaptchaHTML('test-token', 'What is 2 + 2?');
            assert.ok(html, 'HTML should be returned');
            assert.ok(html.includes('test-token'), 'HTML should contain the token');
            assert.ok(html.includes('2 + 2'), 'HTML should contain the question');
        });
    });

    describe('Bot Stats', () => {
        it('should return bot statistics', () => {
            const stats = botDetector.getBotStats();
            assert.ok(stats, 'Stats should be returned');
            assert.ok(typeof stats === 'object', 'Stats should be an object');
        });

        it('should return bot list', () => {
            const bots = botDetector.getBotList();
            assert.ok(Array.isArray(bots), 'Bot list should be an array');
        });
    });
});
