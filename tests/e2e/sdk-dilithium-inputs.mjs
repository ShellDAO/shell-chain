#!/usr/bin/env node
// Exact published SDK input generation and real provider/RPC submission.
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
const child=process.env.SHELL_SDK_CONSUMER_CHILD==='1';
const args=process.argv.slice(child?1:2);
const [mode, rawConsumer, rawInputs, rawIndex, endpoint] = args;
const consumer=resolve(rawConsumer), inputs=resolve(rawInputs);
if(!child) {
  const source=await readFile(new URL(import.meta.url),'utf8');
  const result=spawnSync(process.execPath,['--input-type=module','--eval',source,...args],{cwd:consumer,env:{...process.env,SHELL_SDK_CONSUMER_CHILD:'1'},stdio:'inherit'});
  if(result.error) throw result.error;
  process.exit(result.status??1);
}
const pkg=JSON.parse(await readFile(join(consumer,'node_modules/shell-sdk/package.json'),'utf8'));
if(pkg.version!=='0.14.0-rc.3') throw new Error('exact published SDK candidate required');
const api=async name=>import(`shell-sdk/${name}`);
if(mode==='prepare') {
  const {MlDsa65Adapter}=await api('adapters');
  const {ShellSigner}=await api('signer');
  const {buildTransferTransaction}=await api('transactions');
  const adapter=MlDsa65Adapter.generate(), signer=new ShellSigner('Dilithium3',adapter);
  try {
    const signed=[];
    for(const nonce of [0,1]) {
      const tx=buildTransferTransaction({chainId:10,nonce,to:`0x${'11'.repeat(32)}`,value:1n,gasLimit:21000,maxFeePerGas:2,maxPriorityFeePerGas:1});
      signed.push(await signer.buildSignedTransaction({tx,includePublicKey:false}));
    }
    await writeFile(inputs,JSON.stringify({package:'shell-sdk',version:pkg.version,signature_type:'Dilithium3',public_key:Array.from(adapter.getPublicKey()),address:signer.getAddress(),signed,private_keys_persisted:false},null,2)+'\n',{flag:'wx'});
  } finally { signer.dispose(); }
} else if(mode==='send') {
  const {createShellProvider}=await api('provider');
  const data=JSON.parse(await readFile(inputs,'utf8'));
  const signed=data.signed[Number(rawIndex)];
  if(!signed || !endpoint) throw new Error('retained signed input/endpoint absent');
  const provider=createShellProvider({rpcHttpUrl:endpoint});
  const hash=await provider.sendTransaction(signed);
  console.log(JSON.stringify({hash,public_package:pkg.version,selected_algorithm:'Dilithium3',real_provider_rpc:true}));
} else if(mode==='refuse') {
  const {createShellProvider}=await api('provider');
  const data=JSON.parse(await readFile(inputs,'utf8'));
  const signed=structuredClone(data.signed[Number(rawIndex)]);
  signed.tx.value='0x2';
  const provider=createShellProvider({rpcHttpUrl:endpoint});
  let rejection;
  try { await provider.sendTransaction(signed); } catch(error) { rejection=String(error); }
  if(!rejection || !/signature/i.test(rejection)) throw new Error(`wrong SDK tamper rejection: ${rejection}`);
  console.log(JSON.stringify({rejected:true,error:rejection,real_provider_rpc:true,original_signed_input_unchanged:true}));
} else if(mode==='receipt') {
  const {createShellProvider}=await api('provider');
  const provider=createShellProvider({rpcHttpUrl:endpoint});
  const result=await provider.client.getTransactionReceipt({hash:rawIndex});
  if(result.status!=='success') throw new Error('SDK observed failed receipt');
  console.log(JSON.stringify({hash:result.transactionHash,status:result.status,gas_used:result.gasUsed.toString(),real_provider_rpc:true}));
} else { throw new Error('prepare|send|receipt expected'); }
