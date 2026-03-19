/**
 * Lightweight GeoIP Lookup Module
 * 
 * Maps IP addresses to country codes and names using:
 *   1. MaxMind GeoLite2 database (if available)
 *   2. Built-in heuristic table (fallback)
 *   3. ip-api.com async lookup (cached)
 * 
 * MaxMind requires:
 *   - `npm install maxmind` (listed as optionalDependency)
 *   - Place GeoLite2-Country.mmdb in ./data/
 */

'use strict';

const http = require('http');
const path = require('path');
const fs = require('fs');

// ---------- MaxMind GeoLite2 (optional) ----------
let maxmindReader = null;
const MMDB_PATHS = [
    path.join(__dirname, 'data', 'GeoLite2-Country.mmdb'),
    path.join(__dirname, 'data', 'GeoLite2-City.mmdb'),
    '/usr/share/GeoIP/GeoLite2-Country.mmdb',
];

function _initMaxMind() {
    try {
        const maxmind = require('maxmind');
        for (const mmdbPath of MMDB_PATHS) {
            if (fs.existsSync(mmdbPath)) {
                maxmindReader = maxmind.openSync(mmdbPath);
                return true;
            }
        }
    } catch {
        // maxmind package not installed — use heuristic fallback
    }
    return false;
}

function _maxmindLookup(ip) {
    if (!maxmindReader) return null;
    try {
        const result = maxmindReader.get(ip);
        if (!result || !result.country) return null;
        const cc = result.country.iso_code || 'XX';
        return {
            country: cc,
            countryName: result.country.names?.en || COUNTRY_NAMES[cc] || 'Unknown',
            city: result.city?.names?.en || '',
            lat: result.location?.latitude || 0,
            lon: result.location?.longitude || 0,
        };
    } catch {
        return null;
    }
}

// Try to initialize MaxMind on module load
const maxmindAvailable = _initMaxMind();

// Country code → name map (ISO 3166-1 alpha-2)
const COUNTRY_NAMES = {
    'US': 'United States', 'CN': 'China', 'RU': 'Russia', 'DE': 'Germany', 'FR': 'France',
    'GB': 'United Kingdom', 'JP': 'Japan', 'IN': 'India', 'BR': 'Brazil', 'KR': 'South Korea',
    'AU': 'Australia', 'CA': 'Canada', 'IT': 'Italy', 'NL': 'Netherlands', 'ES': 'Spain',
    'SE': 'Sweden', 'NO': 'Norway', 'FI': 'Finland', 'DK': 'Denmark', 'PL': 'Poland',
    'UA': 'Ukraine', 'RO': 'Romania', 'CZ': 'Czech Republic', 'AT': 'Austria', 'CH': 'Switzerland',
    'BE': 'Belgium', 'PT': 'Portugal', 'IE': 'Ireland', 'IL': 'Israel', 'SG': 'Singapore',
    'HK': 'Hong Kong', 'TW': 'Taiwan', 'TH': 'Thailand', 'VN': 'Vietnam', 'ID': 'Indonesia',
    'MY': 'Malaysia', 'PH': 'Philippines', 'TR': 'Turkey', 'SA': 'Saudi Arabia', 'AE': 'UAE',
    'EG': 'Egypt', 'ZA': 'South Africa', 'NG': 'Nigeria', 'KE': 'Kenya', 'AR': 'Argentina',
    'MX': 'Mexico', 'CO': 'Colombia', 'CL': 'Chile', 'PE': 'Peru', 'VE': 'Venezuela',
    'NZ': 'New Zealand', 'IR': 'Iran', 'IQ': 'Iraq', 'PK': 'Pakistan', 'BD': 'Bangladesh',
    'LK': 'Sri Lanka', 'MM': 'Myanmar', 'KH': 'Cambodia', 'LA': 'Laos', 'NP': 'Nepal',
    'XX': 'Unknown', '--': 'Private/Reserved'
};

// IP first-octet to likely country (rough estimate for common ranges)
// This is a simplified heuristic — for production use a proper GeoIP database
const FIRST_OCTET_MAP = {
    1: 'US', 2: 'US', 3: 'US', 4: 'US', 6: 'US', 7: 'US', 8: 'US', 9: 'US',
    12: 'US', 13: 'US', 15: 'US', 16: 'US', 17: 'US', 18: 'US', 20: 'US',
    23: 'US', 24: 'US', 32: 'US', 33: 'US', 34: 'US', 35: 'US', 38: 'US', 40: 'US', 44: 'GB',
    45: 'US', 46: 'RU', 47: 'CA', 49: 'US', 50: 'US', 52: 'US', 54: 'US', 55: 'BR',
    58: 'CN', 59: 'CN', 60: 'CN', 61: 'AU', 62: 'DE', 63: 'US', 64: 'US', 65: 'US',
    66: 'US', 67: 'US', 68: 'US', 69: 'US', 70: 'US', 71: 'US', 72: 'US',
    74: 'US', 75: 'US', 76: 'US', 77: 'DE', 78: 'DE', 79: 'FR', 80: 'FR', 81: 'DE',
    82: 'FR', 83: 'FR', 84: 'DE', 85: 'NL', 86: 'CN', 87: 'FR', 88: 'FR', 89: 'FR',
    90: 'FR', 91: 'IN', 92: 'FR', 93: 'FR', 94: 'FR', 95: 'RU', 96: 'US', 97: 'US',
    98: 'US', 99: 'US', 100: 'US', 101: 'CN', 103: 'SG', 104: 'US', 106: 'CN', 108: 'US',
    110: 'CN', 111: 'CN', 112: 'CN', 113: 'JP', 114: 'CN', 115: 'CN', 116: 'CN', 117: 'CN',
    118: 'CN', 119: 'KR', 120: 'CN', 121: 'CN', 122: 'JP', 123: 'CN', 124: 'CN', 125: 'CN',
    128: 'US', 129: 'US', 130: 'DE', 131: 'US', 132: 'US', 133: 'JP', 134: 'US',
    136: 'US', 137: 'US', 138: 'US', 139: 'CN', 140: 'US', 141: 'DE', 142: 'US',
    143: 'US', 144: 'US', 145: 'US', 146: 'US', 147: 'US', 148: 'US', 149: 'US',
    150: 'US', 151: 'US', 152: 'US', 153: 'JP', 154: 'ZA', 155: 'US', 156: 'US',
    157: 'US', 158: 'US', 159: 'US', 160: 'US', 161: 'US', 162: 'US', 163: 'CN',
    164: 'US', 165: 'US', 166: 'US', 167: 'US', 168: 'US', 169: 'US', 170: 'AR',
    171: 'BR', 172: 'US', 173: 'US', 174: 'US', 175: 'CN', 176: 'RU', 177: 'BR',
    178: 'RU', 179: 'BR', 180: 'CN', 181: 'AR', 182: 'CN', 183: 'CN', 184: 'US',
    185: 'RU', 186: 'BR', 187: 'BR', 188: 'RU', 189: 'MX', 190: 'CO', 191: 'BR',
    192: 'US', 193: 'DE', 194: 'DE', 195: 'DE', 196: 'ZA', 197: 'EG', 198: 'US',
    199: 'US', 200: 'BR', 201: 'MX', 202: 'AU', 203: 'AU', 204: 'US', 205: 'US',
    206: 'US', 207: 'US', 208: 'US', 209: 'US', 210: 'CN', 211: 'KR', 212: 'DE',
    213: 'FR', 214: 'US', 215: 'US', 216: 'US', 217: 'DE', 218: 'CN', 219: 'CN',
    220: 'CN', 221: 'CN', 222: 'CN', 223: 'CN'
};

// Cache for API lookups
const geoCache = new Map();

// Check if IP is private/reserved
function isPrivateIp(ip) {
    if (!ip || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
    const clean = ip.replace('::ffff:', '');
    const parts = clean.split('.').map(Number);
    if (parts.length !== 4) return true;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    return false;
}

/**
 * Lookup geolocation for an IP address (synchronous, using heuristic table)
 * Returns { country: 'US', countryName: 'United States', city: '', lat: 0, lon: 0 }
 */
function lookupSync(ip) {
    if (!ip) return { country: '--', countryName: 'Private/Reserved', city: '', lat: 0, lon: 0 };

    const clean = ip.replace('::ffff:', '');

    if (isPrivateIp(clean)) {
        return { country: '--', countryName: 'Private/Reserved', city: '', lat: 0, lon: 0 };
    }

    // Check cache
    if (geoCache.has(clean)) return geoCache.get(clean);

    // Try MaxMind first (accurate)
    const mmResult = _maxmindLookup(clean);
    if (mmResult) {
        geoCache.set(clean, mmResult);
        return mmResult;
    }

    // Fallback to heuristic table
    const firstOctet = parseInt(clean.split('.')[0]);
    const cc = FIRST_OCTET_MAP[firstOctet] || 'XX';
    const result = {
        country: cc,
        countryName: COUNTRY_NAMES[cc] || 'Unknown',
        city: '',
        lat: 0,
        lon: 0
    };
    geoCache.set(clean, result);
    return result;
}

/**
 * Async lookup using free ip-api.com (rate limited, use cautiously)
 * Results are cached.
 */
function lookupAsync(ip) {
    return new Promise((resolve) => {
        const clean = ip.replace('::ffff:', '');
        if (isPrivateIp(clean)) {
            resolve({ country: '--', countryName: 'Private/Reserved', city: '', lat: 0, lon: 0 });
            return;
        }
        if (geoCache.has(clean)) { resolve(geoCache.get(clean)); return; }

        const req = http.get(`http://ip-api.com/json/${clean}?fields=status,country,countryCode,city,lat,lon`, (res) => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    if (data.status === 'success') {
                        const result = { country: data.countryCode, countryName: data.country, city: data.city || '', lat: data.lat || 0, lon: data.lon || 0 };
                        geoCache.set(clean, result);
                        resolve(result);
                    } else {
                        resolve(lookupSync(clean));
                    }
                } catch { resolve(lookupSync(clean)); }
            });
        });
        req.on('error', () => resolve(lookupSync(clean)));
        req.setTimeout(2000, () => { req.destroy(); resolve(lookupSync(clean)); });
    });
}

module.exports = { lookupSync, lookupAsync, isPrivateIp, COUNTRY_NAMES, maxmindAvailable };
