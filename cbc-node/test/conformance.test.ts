import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
// @ts-ignore
const cbc = require('../index.node');

interface TestVector {
    id: string;
    type: "valid" | "invalid";
    description: string;
    artifact_base64: string;
    expected_payload_base64?: string;
    expected_error?: string;
}

interface ConformanceSuite {
    version: string;
    vectors: TestVector[];
}

describe("Universal CBC Conformance Suite (cbc-node)", () => {
    const vectorsPath = path.resolve(__dirname, '../../cbc-core/tests/conformance/vectors.json');
    const suite: ConformanceSuite = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'));

    suite.vectors.forEach((vector) => {
        it(`Vector ${vector.id}: ${vector.description}`, () => {
            const artifact = Buffer.from(vector.artifact_base64, 'base64');
            const tmpPath = path.join(os.tmpdir(), `cbc_conformance_${vector.id}.cbc`);
            fs.writeFileSync(tmpPath, artifact);

            try {
                if (vector.type === 'valid') {
                    const isValid = cbc.validateFile(tmpPath);
                    expect(isValid).toBe(true);
                } else if (vector.type === 'invalid') {
                    let threw = false;
                    let errMsg = "";
                    try {
                        const isValid = cbc.validateFile(tmpPath);
                        if (!isValid) threw = true;
                    } catch (e: any) {
                        threw = true;
                        errMsg = e.message || e.toString();
                    }
                    expect(threw).toBe(true);

                    if (vector.expected_error && errMsg) {
                        expect(errMsg).toContain(vector.expected_error);
                    }
                }
            } finally {
                if (fs.existsSync(tmpPath)) {
                    fs.unlinkSync(tmpPath);
                }
            }
        });
    });
});
