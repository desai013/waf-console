/**
 * Input Validation Middleware
 * ============================
 * Schema-based validation using Joi for all API inputs.
 *
 * Usage:
 *   const { validate, schemas } = require('./validator');
 *   app.post('/api/sites', validate(schemas.createSite), handler);
 */

let Joi;
try {
    Joi = require('joi');
} catch {
    // LO-02 fix: fail hard — silent validation bypass is a security vulnerability
    console.error('[FATAL] Joi not installed — input validation is required for production.');
    console.error('[FATAL] Run: npm install joi');
    if (process.env.NODE_ENV === 'production') {
        process.exit(1);
    }
    Joi = null; // dev/test only: allow startup without Joi
}

// ============================================================================
// Schemas
// ============================================================================

const schemas = {};

if (Joi) {
    schemas.createSite = Joi.object({
        name: Joi.string().min(1).max(200).required(),
        domain: Joi.string().hostname().required(),
        targetUrl: Joi.string().uri({ scheme: ['http', 'https'] }).required(),
        waf_mode: Joi.string().valid('BLOCKING', 'DETECTION').default('BLOCKING'),
        enabled: Joi.boolean().default(true),
    });

    schemas.updateSite = Joi.object({
        name: Joi.string().min(1).max(200),
        domain: Joi.string().hostname(),
        target_url: Joi.string().uri({ scheme: ['http', 'https'] }),
        waf_mode: Joi.string().valid('BLOCKING', 'DETECTION'),
        enabled: Joi.boolean(),
    }).min(1);

    schemas.siteMode = Joi.object({
        mode: Joi.string().valid('BLOCKING', 'DETECTION').required(),
    });

    schemas.createWhitelist = Joi.object({
        type: Joi.string().valid('ip', 'uri', 'uri_exact', 'rule', 'ip_rule', 'uri_rule').required(),
        value: Joi.string().min(1).max(500).required(),
        rule_id: Joi.string().allow('', null).max(20),
        reason: Joi.string().allow('', null).max(500),
        source_event_id: Joi.string().allow('', null),
    });

    schemas.updateWhitelist = Joi.object({
        type: Joi.string().valid('ip', 'uri', 'uri_exact', 'rule', 'ip_rule', 'uri_rule'),
        value: Joi.string().min(1).max(500),
        rule_id: Joi.string().allow('', null).max(20),
        reason: Joi.string().allow('', null).max(500),
        enabled: Joi.boolean(),
    }).min(1);

    schemas.createHeaderBlacklist = Joi.object({
        site_id: Joi.number().integer().allow(null),
        header_name: Joi.string().min(1).max(200).required(),
        match_type: Joi.string().valid('contains', 'equals', 'starts_with', 'ends_with', 'regex').default('contains'),
        match_value: Joi.string().min(1).max(1000).required(),
        action: Joi.string().valid('BLOCK', 'LOG').default('BLOCK'),
        reason: Joi.string().allow('', null).max(500),
        created_by: Joi.string().max(100).default('analyst'),
    });

    schemas.createGeoBlacklist = Joi.object({
        site_id: Joi.number().integer().allow(null),
        country_code: Joi.string().length(2).uppercase().required(),
        country_name: Joi.string().min(1).max(100).required(),
        reason: Joi.string().allow('', null).max(500),
    });

    schemas.createUser = Joi.object({
        username: Joi.string().alphanum().min(3).max(50).required(),
        password: Joi.string().min(8).max(128).required(),
        role: Joi.string().valid('admin', 'analyst', 'readonly').default('readonly'),
        displayName: Joi.string().allow('', null).max(100),
    });

    schemas.changePassword = Joi.object({
        currentPassword: Joi.string().required(),
        newPassword: Joi.string().min(8).max(128).required(),
    });

    schemas.createCustomRule = Joi.object({
        name: Joi.string().min(1).max(200).required(),
        attack_type: Joi.string().min(1).max(100).required(),
        severity: Joi.string().valid('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO').default('HIGH'),
        targets: Joi.string().default('["uri"]'),
        pattern: Joi.string().min(1).max(2000).required(),
        action: Joi.string().valid('BLOCK', 'LOG').default('BLOCK'),
    });

    schemas.createPlaybook = Joi.object({
        name: Joi.string().min(1).max(200).required(),
        trigger_type: Joi.string().required(),
        trigger_value: Joi.alternatives().try(Joi.string(), Joi.number()).required(),
        actions: Joi.array().items(Joi.object()).min(1).required(),
        enabled: Joi.boolean().default(true),
    });

    schemas.toggleEnabled = Joi.object({
        enabled: Joi.boolean().required(),
    });

    schemas.markRead = Joi.object({
        id: Joi.string().allow('', null),
    });

    schemas.sandboxTest = Joi.object({
        pattern: Joi.string().min(1).max(2000).required(),
        targets: Joi.array().items(Joi.string()).default(['uri']),
        testInputs: Joi.array().items(Joi.string()).min(1).required(),
    });
}

// ============================================================================
// Middleware Factory
// ============================================================================

/**
 * Express middleware that validates req.body against a Joi schema.
 * @param {Object} schema - Joi schema object
 * @param {string} [source='body'] - Request property to validate ('body', 'query', 'params')
 */
function validate(schema, source = 'body') {
    return (req, res, next) => {
        // If Joi not installed, skip validation
        if (!Joi || !schema) return next();

        const data = req[source];
        const { error, value } = schema.validate(data, {
            abortEarly: false,
            stripUnknown: true,
            convert: true,
        });

        if (error) {
            const details = error.details.map(d => ({
                field: d.path.join('.'),
                message: d.message,
            }));
            return res.status(400).json({
                error: 'Validation failed',
                details,
            });
        }

        // Replace req[source] with validated and sanitized data
        req[source] = value;
        next();
    };
}

module.exports = { validate, schemas };
