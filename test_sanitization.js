const sanitizeHtml = require('sanitize-html');
const payload = '<iframe src="javascript:alert(`xss`)">';
const sanitized = sanitizeHtml(payload);
console.log('Payload:', payload);
console.log('Sanitized:', sanitized);
if (sanitized === payload) {
    console.log('VULNERABLE: Payload was not sanitized!');
} else {
    console.log('SAFE: Payload was sanitized.');
}
