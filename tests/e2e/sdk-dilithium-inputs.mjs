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
if(mode==='proposer') {
  const {createInterface}=await import('node:readline');
  const {MlDsa65Adapter}=await api('adapters');
  const {ShellSigner}=await api('signer');
  const signer=new ShellSigner('Dilithium3',MlDsa65Adapter.generate());
  const data={version:pkg.version,native_algorithm:'Dilithium3',public_key:Array.from(signer.getPublicKey()),address:signer.getAddress(),requests:[],private_keys_persisted:false,disposed:false};
  const emit=value=>new Promise((resolve,reject)=>process.stdout.write(JSON.stringify(value)+'\n',error=>error?reject(error):resolve()));
  const save=()=>writeFile(inputs,JSON.stringify(data,null,2)+'\n');
  await writeFile(inputs,JSON.stringify(data,null,2)+'\n',{flag:'wx'});
  await emit({kind:'ready',version:pkg.version,public_key:data.public_key,address:data.address,private_keys_persisted:false});
  const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
  try {
    for await (const line of lines) {
      const request=JSON.parse(line);
      if(request.stop===true) break;
      if(!Array.isArray(request.message)||request.message.length!==32) throw new Error('raw32 Native header/vote hash required');
      const signature={sig_type:'Dilithium3',data:Array.from(await signer.sign(Uint8Array.from(request.message)))};
      data.requests.push({message:request.message,signature,actual_public_signer:true});
      await save();
      await emit({kind:'signature',signature,actual_public_signer:true});
    }
  } finally { lines.close();signer.dispose();data.disposed=true;await save(); }
  await emit({kind:'stopped',disposed:true});
  process.stdin.pause();
  process.exit(0);
} else if(mode==='prepare'||mode==='prepare-unbound') {
  const unbound=mode==='prepare-unbound';
  const {MlDsa65Adapter}=await api('adapters');
  const {ShellSigner}=await api('signer');
  const {buildTransferTransaction}=await api('transactions');
  const adapter=MlDsa65Adapter.generate(), signer=new ShellSigner('Dilithium3',adapter);
  try {
    const signed=[];
    for(const nonce of (unbound?[0,1,2]:[0,1])) {
      const tx=buildTransferTransaction({chainId:10,nonce,to:`0x${'11'.repeat(32)}`,value:1n,gasLimit:21000,maxFeePerGas:2,maxPriorityFeePerGas:1});
      signed.push(await signer.buildSignedTransaction(unbound&&nonce===0?{tx,includePublicKey:true}:{tx,includePublicKey:false}));
    }
    await writeFile(inputs,JSON.stringify({package:'shell-sdk',version:pkg.version,signature_type:'Dilithium3',public_key:Array.from(adapter.getPublicKey()),address:signer.getAddress(),signed,private_keys_persisted:false,...(unbound?{unbound_sender:true}:{})},null,2)+'\n',{flag:'wx'});
  } finally { signer.dispose(); }
} else if(mode==='send') {
  const {createShellProvider}=await api('provider');
  const data=JSON.parse(await readFile(inputs,'utf8'));
  const signed=data.signed[Number(rawIndex)];
  if(!signed || !endpoint) throw new Error('retained signed input/endpoint absent');
  const provider=createShellProvider({rpcHttpUrl:endpoint});
  const hash=await provider.sendTransaction(signed);
  console.log(JSON.stringify({hash,public_package:pkg.version,selected_algorithm:'Dilithium3',real_provider_rpc:true}));
} else if(['refuse','refuse-reference','refuse-address'].includes(mode)) {
  const {createShellProvider}=await api('provider');
  const data=JSON.parse(await readFile(inputs,'utf8'));
  const signed=structuredClone(data.signed[Number(rawIndex)]);
  if(mode==='refuse-reference') { signed.sender_pubkey=null; }
  else if(mode==='refuse-address') { signed.from=`0x${'11'.repeat(32)}`; }
  else { signed.tx.value='0x2'; }
  const provider=createShellProvider({rpcHttpUrl:endpoint});
  let rejection;
  try { await provider.sendTransaction(signed); } catch(error) { rejection=String(error); }
  if(!rejection || !(mode==='refuse'?/signature/i:mode==='refuse-reference'?/public.key|pubkey|reference/i:/address|sender|account|key/i).test(rejection)) throw new Error(`wrong SDK tamper rejection: ${rejection}`);
  console.log(JSON.stringify({rejected:true,error:rejection,real_provider_rpc:true,original_signed_input_unchanged:true}));
} else if(mode==='receipt') {
  const {createShellProvider}=await api('provider');
  const provider=createShellProvider({rpcHttpUrl:endpoint});
  const result=await provider.client.getTransactionReceipt({hash:rawIndex});
  if(result.status!=='success') throw new Error('SDK observed failed receipt');
  console.log(JSON.stringify({hash:result.transactionHash,status:result.status,gas_used:result.gasUsed.toString(),real_provider_rpc:true}));
} else { throw new Error('prepare|send|receipt expected'); }
