import fs from 'fs';
import path from 'path';
import {fileURLToPath} from 'url';
import Ajv from 'ajv/dist/2020.js';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(currentDir, '../../..');
const schemaPath = path.join(projectRoot, 'schemas/receipt-v1.schema.json');
const vectorsDir = path.join(projectRoot, 'schemas/vectors');
const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
const ajv = new Ajv({strict: true, allErrors: true});
const validate = ajv.compile(schema);

function loadVectors(dir) {
  return fs
    .readdirSync(dir)
    .filter(file => file.endsWith('.json'))
    .map(file => path.join(dir, file));
}

for (const file of loadVectors(path.join(vectorsDir, 'valid'))) {
  const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
  if (!validate(data)) {
    console.error('expected valid but failed:', file, validate.errors);
    process.exit(1);
  }
}

for (const file of loadVectors(path.join(vectorsDir, 'invalid'))) {
  const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
  if (validate(data)) {
    console.error('expected invalid but passed:', file);
    process.exit(1);
  }
}

console.log('all vectors validated successfully.');
