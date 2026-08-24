const cp = require('child_process');
const { globSync } = require('glob');

const serverTests = globSync('test/server/**/*.unit.test.ts');
console.log(`Found ${serverTests.length} server unit tests.`);

const apiTests = globSync('test/api/**/*.test.ts');
console.log(`Found ${apiTests.length} API tests.`);

console.log('Running Server Unit Tests...');
const serverProc = cp.spawnSync('node', [
  '--import', './test/override-version.mjs',
  '--import', './test/server/helpers/test-env.mjs',
  '--import', 'tsx',
  '--test',
  '--test-force-exit',
  ...serverTests
], { stdio: 'inherit' });

if (serverProc.status !== 0) {
  console.error('Server Unit Tests failed!');
  process.exit(serverProc.status || 1);
}

console.log('Running API Tests...');
const apiProc = cp.spawnSync('node', [
  '--import', './test/override-version.mjs',
  '--import', './test/api/helpers/test-env.mjs',
  '--import', 'tsx',
  '--test',
  '--test-force-exit',
  ...apiTests
], { stdio: 'inherit' });

if (apiProc.status !== 0) {
  console.error('API Tests failed!');
  process.exit(apiProc.status || 1);
}

console.log('All tests passed successfully!');
process.exit(0);
