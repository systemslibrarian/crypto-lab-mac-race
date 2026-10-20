// Concrete-patch workflow adapted from check-crc-mutations.mjs; CRC runner unchanged.
import {readFileSync,writeFileSync,readdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const cases=[
 {name:'splice loses XOR',file:'src/cbcmac/forge.ts',anchor:'forged.set(xor(m, t), 16)',replacement:'forged.set(xor(m, new Uint8Array(t.length)), 16)',test:'CBC-MAC one-query splice'},
 {name:'variable receiver gains length restriction',file:'src/cbcmac/cbcmac.ts',anchor:'export async function verifyAnyLength(key: Uint8Array, message: Uint8Array, tag: Uint8Array): Promise<Verification> {\n  return verifyRaw(key, message, tag);',replacement:'export async function verifyAnyLength(key: Uint8Array, message: Uint8Array, tag: Uint8Array): Promise<Verification> {\n  return verifyFixedLength(key, message, tag, 16);',test:'CBC-MAC one-query splice'},
 {name:'length-prepending drops its length block',file:'src/cbcmac/cbcmac.ts',anchor:'return rawCbcMac(key, framed);',replacement:'return rawCbcMac(key, framed.subarray(16));',test:'CBC-MAC fixes reject'},
 {name:'accepted forgery painted calm',file:'src/cbcmac/panel.ts',anchor:"chip(v, result.accepted ? 'alarm' : 'accept', result.accepted ? '✕ ACCEPTED — FORGED'",replacement:"chip(v, result.accepted ? 'accept' : 'accept', result.accepted ? '✕ ACCEPTED — FORGED'",test:'CBC-MAC one-query splice'},
 {name:'complete CMAC block uses K2',file:'src/cmac.ts',anchor:'xorBlock(paddedLastBlock, complete ? k1 : k2)',replacement:'xorBlock(paddedLastBlock, k2)',test:'RFC 4493 AES-128 16-byte message',unit:true},
 {name:'missing CBC-MAC negative claim',file:'src/cbcmac/panel.ts',anchor:'export const CBC_NEGATIVE = "A valid raw CBC-MAC tag does not authenticate the message\'s length: when the receiver accepts more than one length, every check this verifier performs passes on a message nobody tagged.";',replacement:'export const CBC_NEGATIVE = "";',test:'CBC-MAC one-query splice'},
];
const run=(command,args,extra={})=>{const r=spawnSync(command,args,{encoding:'utf8',timeout:120000,env:{...process.env,CI:'1',...extra}});return {status:r.status,output:(r.stdout??'')+'\n'+(r.stderr??'')};};
function requirePass(r,label){if(r.status!==0)throw new Error(label+'\n'+r.output);}
function assets(){return Object.fromEntries(readdirSync('dist/assets').filter(f=>f.endsWith('.js')).sort().map(f=>[f,createHash('sha256').update(readFileSync('dist/assets/'+f)).digest('hex')]));}
const hash=()=>createHash('sha256').update(JSON.stringify(assets())).digest('hex');
function owning(e){return e.unit?run('npx',['vitest','run','src/cbcmac/cbcmac.test.ts','-t',e.test]):run('npx',['playwright','test',...(process.env.PLAYWRIGHT_CONFIG?['--config',process.env.PLAYWRIGHT_CONFIG]:[]),'--project=chromium','e2e/claims.spec.ts','--grep',e.test,'--retries=0'],{MUTATION_ASSETS:JSON.stringify(assets())});}
const records=[];
for(const e of cases){
 const source=readFileSync(e.file,'utf8');if(source.split(e.anchor).length!==2)throw new Error(e.name+': ambiguous anchor');
 requirePass(run('npm',['run','build']),e.name+' baseline build');const baseline=hash(),before=owning(e);requirePass(before,e.name+' baseline test');if(!/1 passed/.test(before.output))throw new Error('Owning test did not run exactly once');
 let mutant='',sourceDiff='',failure,restoredGreen=false;
 try{
  writeFileSync(e.file,source.replace(e.anchor,e.replacement));sourceDiff=run('git',['diff','--',e.file]).output.trim();if(!sourceDiff)throw new Error('No source patch');
  requirePass(run('npm',['run','build']),e.name+' mutant build');mutant=hash();if(mutant===baseline)throw new Error('Mutation did not change build');failure=owning(e);
 }finally{
  writeFileSync(e.file,source);requirePass(run('npm',['run','build']),e.name+' restore build');if(hash()!==baseline)throw new Error('Build not byte-exact restored');
  const restored=owning(e);requirePass(restored,e.name+' restored test');restoredGreen=/1 passed/.test(restored.output);
 }
 const assertionFailure=failure.status!==0&&/AssertionError|Error: expect\(|expect\(received\)/.test(failure.output)&&failure.output.includes(e.test)&&!failure.output.includes('MUTATION_ASSET_MISMATCH')&&!failure.output.includes('Process from config.webServer');
 if(!assertionFailure||!restoredGreen)throw new Error(e.name+' did not fail a named assertion\n'+failure.output);
 records.push({name:e.name,sourceDiff,baseline,mutant,owningTest:e.test,unit:!!e.unit,baselinePassed:true,mutantBuilt:true,assertionFailure,retries:0,servedAssetGuard:!e.unit,restoredGreen,restoredHash:hash()});
 console.log(e.name+': killed; exact build restored; owning test green');
}
writeFileSync('cbcmac-mutation-evidence.json',JSON.stringify(records,null,2)+'\n');
