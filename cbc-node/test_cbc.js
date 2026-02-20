const { inspectFile, validateFile } = require('./index.node');
const path = require('path');

const artifactPath = path.resolve('../test.cbc');

console.log(`Testing cbc-node with ${artifactPath}...`);

try {
    const info = inspectFile(artifactPath);
    console.log('\n[Inspection Result]');
    console.log(`Valid Bootstrap: ${info.validBootstrap}`);
    console.log(`Hash Suite: ${info.hashSuite}`);
    console.log(`Block Size: ${info.blockPayloadSize}`);
    console.log(`Families: ${info.families.join(', ')}`);
} catch (err) {
    console.error(`Inspection failed: ${err.message}`);
    process.exit(1);
}

try {
    const isValid = validateFile(artifactPath);
    console.log(`\nValidation Status: ${isValid ? '✓ VALID' : '✗ INVALID'}`);
} catch (err) {
    console.error(`Validation failed: ${err.message}`);
    process.exit(1);
}
