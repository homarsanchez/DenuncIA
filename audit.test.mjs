import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes,createPrivateKey,webcrypto} from 'node:crypto';
import 'reflect-metadata';
import {X509CertificateGenerator} from '@peculiar/x509';
import {analyze,sha} from './analysis.mjs';
import {makeFiles,makeSigner,verifyXml,batchZip} from './documents.mjs';
import {verifyBundle} from './verify.mjs';
import AdmZip from 'adm-zip';
const ah='EJERCICIO,DEPENDENCIA,CLAVEUC,CODIGO_CONTRATO,NUMERO_PROCEDIMIENTO,TITULO_CONTRATO,TIPO_CONTRATACION,TIPO_PROCEDIMIENTO,IMPORTE_CONTRATO,MONEDA,PROVEEDOR_CONTRATISTA,FECHA_CELEBRACION';
const bh='date,buyer_id,suppliers,tenderers,hasenquiries,method,amount,status,winner';
const data=(name,text,enc='utf8')=>({name,bytes:Buffer.from(text,enc)});
const a=(ord,title='Equipos de ejemplo',date=`0${ord}/01/2019`,person='Proveedor X',proc='P'+ord)=>`2019,Institución X,4,ID${ord},${proc},${title},Bienes,Adjudicación directa,1000,MXN,${person},${date}`;
const b=data('b.csv',bh+'\r\n01-02,C1,1,-1,false,direct,0,complete,Z\r\n');
const example=()=>{const rows=[a(1,'"Equipos de\r\nejemplo"'),a(2),a(3)];return [data('a.csv','\uFEFF'+ah+'\r\n\r\n'+rows.join('\r\n')+'\r\n'),rows]};
test('adjudicación directa no basta y se excluyen el año ausente y las ofertas negativas',()=>{
  const r=analyze(data('a.csv',ah+'\n'+a(1)+'\n'+a(2)),b);
  assert.equal(r.cases.length,0);assert.equal(r.profile.b.missingYear,1);assert.equal(r.profile.b.negatives,1);assert.equal(r.profile.b.zeroAmounts,1);
  const repeats=[a(1),a(2,'Equipos de ejemplo',undefined,undefined,'P1'),a(3)];
  assert.equal(analyze(data('a.csv',ah+'\n'+repeats.join('\n')),b).cases.length,0);
  assert.throws(()=>analyze(b,b),/encabezados/);
});
test('tres procedimientos distintos: hipótesis, no imputación; adjunto exacto incluso con BOM, tildes, CRLF y salto interno',()=>{
  const [input,rows]=example();const r=analyze(input,b);
  assert.equal(r.cases.length,3);assert.equal(r.profile.article217,3);
  const c=r.cases.find(c=>c.contract==='ID1');assert.match(c.person,/No identificada/);const principal=c.evidence[0].c.d;
  assert.equal(r.sources.a.header.toString(),'\uFEFF'+ah+'\r\n');assert.deepEqual([principal.first,principal.last],[3,4]);assert.equal(principal.bytes.toString(),rows[0]+'\r\n');
  const legacy=analyze(data('latin.csv',ah+'\r\n'+[a(1),a(2),a(3)].join('\r\n'),'latin1'),b);
  assert.equal(legacy.cases[0].evidence[0].c.d.bytes.toString('latin1'),a(1)+'\r\n');
});
test('acta firmada, PDF, ZIP y manifiesto; mutar XML o un adjunto falla',async()=>{
  const r=analyze(example()[0],b);r.signer=await makeSigner();r.cache=new Map();const c=r.cases[0];
  const files=await makeFiles(c,r);assert.ok(await verifyXml(files.xml));assert.ok(!await verifyXml(files.xml.toString().replace('Borrador de triaje','Alterado')));assert.ok(files.pdf.subarray(0,5).equals(Buffer.from('%PDF-')));
  const z=new AdmZip(await batchZip(r.cases,r));assert.equal(z.getEntries().length,10);
  const temp=mkdtempSync(join(process.env.DENUNCIA_TEST_TMP||tmpdir(),'denuncia-test-'));
  try{
    for(const [ext,value] of Object.entries(files))writeFileSync(join(temp,`${c.id}.${ext}`),value);
    const p=join(temp,c.id+'.xml');assert.equal(verifyBundle(p,r.signer.fingerprint).anexos,2);
    const ev=JSON.parse(files['evidencias.json']);for(const row of ev.registros)assert.equal(row.sha256,sha(Buffer.from(row.registroCSVBase64,'base64')));
    r.cache.clear();assert.ok((await makeFiles(c,r)).pdf.equals(files.pdf));
    writeFileSync(join(temp,c.id+'.pdf'),Buffer.from('modificado'));assert.throws(()=>verifyBundle(p),/alterado/);
  }finally{rmSync(temp,{recursive:true,force:true});}
});
test('carga una llave .KEY PKCS#8 cifrada con .CER autofirmado; contraseña errónea se rechaza',async()=>{
  const alg={name:'RSASSA-PKCS1-v1_5',hash:'SHA-256',modulusLength:2048,publicExponent:new Uint8Array([1,0,1])};
  const keys=await webcrypto.subtle.generateKey(alg,true,['sign','verify']);
  const cert=Buffer.from((await X509CertificateGenerator.createSelfSigned({name:'CN=Prueba local',keys,signingAlgorithm:alg},webcrypto)).rawData);
  const raw=Buffer.from(await webcrypto.subtle.exportKey('pkcs8',keys.privateKey));const password=randomBytes(20).toString('hex');
  const key=createPrivateKey({key:raw,format:'der',type:'pkcs8'}).export({type:'pkcs8',format:'der',cipher:'aes-256-cbc',passphrase:password});
  assert.equal((await makeSigner({key,cert,password})).mode,'Autofirmado local de prueba');
  await assert.rejects(makeSigner({key,cert,password:password+'X'}),/contraseña/);
});
