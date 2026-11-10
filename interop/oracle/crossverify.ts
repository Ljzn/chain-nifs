/** JSON stdin cross-verification or fresh randomized wallet signatures on stdout. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { createHash } from 'node:crypto';
import { mldsa65Sign, mldsa65Verify, encodePkBlob } from './official/pq/mldsa.js';
import { buildPqTreasury, isV2ScriptPubKey } from './official/pq/address.js';
import { NETWORKS } from './official/network.js';
import { Transaction } from './official/signer/transaction.js';
import { pqSighash } from './official/pq/sighash.js';

function verifyPayment(payment: any, index: number) {
 try {
  const raw=hex.decode(payment.rawTxHex), publicKey=hex.decode(payment.publicKeyHex);
  assert.equal(raw[4],0,'payment must use witness serialization');
  assert.equal(raw[5],1,'payment must have witness flag only, without extensions');
  const tx=Transaction.fromRaw(raw,{allowUnknownInputs:true,allowUnknownOutputs:true});
  assert.equal(tx.version,2,'payment version must be 2');
  assert.equal(tx.lockTime,0,'payment locktime must be 0');
  assert.equal(tx.hex,hex.encode(raw),'payment must round-trip byte-for-byte');
  assert(Array.isArray(payment.inputs)&&payment.inputs.length>0,'payment inputs required');
  assert.equal(tx.inputsLength,payment.inputs.length,'input count mismatch');
  assert(tx.outputsLength>0,'payment outputs required');
  // Network changes the HRP only; all networks share these exact policy/script bytes.
  const descriptor=buildPqTreasury(1,[encodePkBlob(publicKey)],NETWORKS.regtest);
  const policy={threshold:1,members:descriptor.members,leafScript:descriptor.script,leafHash:descriptor.leafHash,controlBlock:descriptor.controlBlock};
  let inputSats=0n,outputSats=0n;
  for(let i=0;i<payment.inputs.length;i++) {
   const expected=payment.inputs[i], actual=tx.getInput(i);
   assert.equal(hex.encode(actual.txid!),hex.encode(hex.decode(expected.txid)),'input txid mismatch');
   assert.equal(actual.index,expected.vout,'input vout mismatch');
   assert(Number.isInteger(expected.sequence)&&expected.sequence>=0&&expected.sequence<=0xffffffff,'input sequence must be an integer u32');
   assert.equal(actual.sequence,expected.sequence,'input sequence mismatch');
   assert.equal(actual.finalScriptSig?.length??0,0,'payment scriptSig must be empty');
   assert(typeof expected.amount==='string'&&/^(0|[1-9][0-9]*)$/.test(expected.amount),'amount must be decimal sats string');
   const amount=BigInt(expected.amount);assert(amount<=0xffffffffffffffffn,'amount exceeds u64');inputSats+=amount;
   const witness=actual.finalScriptWitness!;
   assert(Array.isArray(witness)&&witness.length===3,'1of1 witness must have exactly three items');
   assert.equal(witness[0].length,3310,'witness signature must be 3309 bytes plus hashtype');
   assert.equal(witness[0][3309],1,'witness signature hashtype must be 01');
   assert.equal(hex.encode(witness[1]),hex.encode(descriptor.script),'witness leaf differs from official 1of1 policy');
   assert.equal(hex.encode(witness[2]),hex.encode(descriptor.controlBlock),'witness control block differs from official 1of1 policy');
   tx.updateInput(i,{witnessUtxo:{amount,script:descriptor.scriptPubKey}},true);
   tx.setPqPolicy(i,policy);
  }
  for(let i=0;i<tx.outputsLength;i++) {
   const out=tx.getOutput(i);
   assert.equal(out.outext?.length??0,0,'output extension forbidden');
   assert(isV2ScriptPubKey(out.script!),'payment outputs must be witness v2');
   outputSats+=out.amount!;
  }
  assert(inputSats>=outputSats,'outputs exceed spent amounts');
  const sighashesHex=payment.inputs.map((_:any,i:number)=>{
   const digest=tx.getPqSighash(i);
   assert.equal(hex.encode(digest),hex.encode(pqSighash({...tx.getMLDSASighashData(i),inputIndex:i,leaf:{script:descriptor.script}})),'official sighash implementations disagree');
   assert(mldsa65Verify(publicKey,digest,tx.getInput(i).finalScriptWitness![0].subarray(0,3309)),'payment witness signature does not verify');
   return hex.encode(digest);
  });
  assert.equal(tx.hex,hex.encode(raw),'prevout attachment changed serialized payment');
  const hash256=(b:Uint8Array)=>createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
  return {index,verified:true,txid:tx.id,wtxid:hex.encode(hash256(raw).reverse()),sighashesHex,weight:tx.weight,vsize:tx.vsize,feeSats:(inputSats-outputSats).toString()};
 } catch(error) {
  return {index,verified:false,error:error instanceof Error?error.message:String(error)};
 }
}
if(process.argv.includes('--emit')) {
 const fixture=JSON.parse(readFileSync(new URL('../../test/fixtures/wallet-oracle-v1.json',import.meta.url),'utf8'));
 const cases=fixture.keygen.map((k:any)=>{
  const msg32Hex=fixture.signatures.find((s:any)=>s.keyId===k.id).msg32Hex;
  const signatureHex=hex.encode(mldsa65Sign(hex.decode(k.secretKeyHex),hex.decode(msg32Hex)));
  assert(mldsa65Verify(hex.decode(k.publicKeyHex),hex.decode(msg32Hex),hex.decode(signatureHex)));
  return {id:k.id,publicKeyHex:k.publicKeyHex,msg32Hex,signatureHex};
 });
 console.log(JSON.stringify({schemaVersion:1,cases},null,2));
} else {
 const input=JSON.parse(readFileSync(0,'utf8'));
 assert.equal(input.schemaVersion,1);
 if(input.payments!==undefined) assert(Array.isArray(input.payments),'payments must be an array');
 const cases=input.cases??[];
 assert(Array.isArray(cases)&&(cases.length>0||(input.payments?.length??0)>0),'signature cases or payments required');
 const results=cases.map((c:any)=>({id:c.id,verified:mldsa65Verify(hex.decode(c.publicKeyHex),hex.decode(c.msg32Hex),hex.decode(c.signatureHex))}));
 const paymentResults=input.payments?.map(verifyPayment);
 console.log(JSON.stringify({schemaVersion:1,results,...(paymentResults===undefined?{}:{paymentResults})},null,2));
 assert(results.every((r:any)=>r.verified),'one or more signatures failed official wallet verification');
 assert(paymentResults===undefined||paymentResults.every((r:any)=>r.verified),'one or more payments failed official wallet verification');
}
