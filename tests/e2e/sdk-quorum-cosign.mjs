#!/usr/bin/env node
// Sign retained raw block hashes with the actual installed SDK adapter.
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const [input, output, moduleRoot = process.cwd()] = process.argv.slice(2);
if (!input || !output) throw new Error('usage: sdk-quorum-cosign.mjs <messages.json> <new-public-signatures.json> [sdk-package-directory]');
const pkg = JSON.parse(await readFile(resolve(moduleRoot, 'package.json'), 'utf8'));
if (pkg.name !== 'shell-sdk') throw new Error('expected an installed or source-built shell-sdk package directory');
const entry = (name) => {
  const target = pkg.exports?.[`./${name}`]?.import;
  if (typeof target !== 'string' || !target.startsWith('./')) throw new Error('SDK import export unavailable');
  return pathToFileURL(resolve(moduleRoot, target)).href;
};
const { generateAdapter } = await import(entry('adapters'));
const { ShellSigner } = await import(entry('signer'));
const value = JSON.parse(await readFile(input, 'utf8'));
if (value.version !== 1 || !Array.isArray(value.messages) || value.messages.length !== 3 || value.messages.some(x => !/^0x[0-9a-f]{64}$/.test(x))) throw new Error('three exact raw block hashes required');
const adapter = generateAdapter('Dilithium3');
const signer = new ShellSigner('Dilithium3', adapter);
try {
  if (signer.algorithmId !== 0) throw new Error('expected SDK Dilithium3 tag');
  const signatures = [];
  for (const message of value.messages) {
    const signature = await signer.sign(Uint8Array.from(Buffer.from(message.slice(2), 'hex')));
    signatures.push({ message, signature: Buffer.from(signature).toString('hex') });
  }
  const result = { version: 1, algorithm: 'Dilithium3', sdkVersion: pkg.version, address: signer.getAddress(), publicKey: Buffer.from(signer.getPublicKey()).toString('hex'), signatures };
  await writeFile(output, JSON.stringify(result) + '\n', { flag: 'wx' });
} finally { signer.dispose(); }
console.log(JSON.stringify({ publicSignaturesWritten: 3, sdkVersion: pkg.version, temporaryKeyDisposed: true }));
