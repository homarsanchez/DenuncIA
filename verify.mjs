import {readFileSync} from 'node:fs';
import {resolve,dirname,basename} from 'node:path';
import {pathToFileURL} from 'node:url';
import {X509Certificate} from 'node:crypto';
import {DOMParser} from '@xmldom/xmldom';
import {SignedXml} from 'xml-crypto';
import {sha} from './analysis.mjs';
const DS='http://www.w3.org/2000/09/xmldsig#',XA='http://uri.etsi.org/01903/v1.3.2#';
const exact=(items,desc)=>{if(items.length!==1)throw new Error(`Se requiere exactamente uno: ${desc}`);return items[0];};
export function verifyBundle(xmlPath,pinned){
  const text=readFileSync(xmlPath,'utf8');if(text.length>1000000||/<!DOCTYPE|<!ENTITY/i.test(text))throw new Error('Formato de XML inválido para esta demo.');
  const doc=new DOMParser().parseFromString(text,'application/xml');const root=doc.documentElement;
  if(root.tagName!=='ActaDenuncIA'||root.getAttribute('modo')!=='demo-local')throw new Error('El archivo no es un acta de esta demo.');
  const sig=exact(doc.getElementsByTagNameNS(DS,'Signature'),'Signature');if(sig.parentNode!==root)throw new Error('Firma inesperada.');
  const certText=exact(sig.getElementsByTagNameNS(DS,'X509Certificate'),'X509Certificate').textContent;
  const cert=new X509Certificate(Buffer.from(certText,'base64'));
  if(cert.subject!==cert.issuer||!cert.verify(cert.publicKey))throw new Error('Se esperaba certificado autofirmado de prueba.');
  const fingerprint=sha(cert.raw);
  if(pinned&&fingerprint!==pinned.toLowerCase().replaceAll(':',''))throw new Error('La huella no coincide con la esperada.');
  const verifier=new SignedXml({publicCert:cert.toString(),getCertFromKeyInfo:()=>null});verifier.loadSignature(sig);
  if(!verifier.checkSignature(text)||verifier.getSignedReferences().length!==2)throw new Error('No pasa XMLDSig con dos referencias.');
  const refs=[...sig.getElementsByTagNameNS(DS,'Reference')];
  const signedProps=exact(sig.getElementsByTagNameNS(XA,'SignedProperties'),'SignedProperties');
  if(!refs.some(r=>r.getAttribute('URI')==='')||!refs.some(r=>r.getAttribute('URI')==='#'+signedProps.getAttribute('Id')&&r.getAttribute('Type')==='http://uri.etsi.org/01903#SignedProperties'))throw new Error('Referencias XAdES inesperadas.');
  const digest=exact(exact(signedProps.getElementsByTagNameNS(XA,'CertDigest'),'CertDigest').getElementsByTagNameNS(DS,'DigestValue'),'DigestValue');
  if(digest.textContent!==Buffer.from(fingerprint,'hex').toString('base64'))throw new Error('Huella XAdES del certificado incorrecta.');
  if(exact(root.getElementsByTagName('HuellaCertificadoSHA256'),'HuellaCertificadoSHA256').textContent!==fingerprint)throw new Error('Huella del certificado no coincide con el manifiesto.');
  const clave=exact(root.getElementsByTagName('ClaveActa'),'ClaveActa').textContent;
  if(!/^DEN-\d{4}-[\dA-F]{8}-\d{4,}$/.test(clave))throw new Error('Clave inválida.');
  const wanted=new Set([`${clave}.pdf`,`${clave}.evidencias.json`]);
  const attachments=exact(root.getElementsByTagName('ArchivosAdjuntos'),'ArchivosAdjuntos').getElementsByTagName('Archivo');
  let count=0;
  for(const a of attachments){
    const name=exact(a.getElementsByTagName('Nombre'),'Nombre').textContent;
    if(name!==basename(name)||!wanted.delete(name))throw new Error('Nombre de anexo no esperado.');
    const b=readFileSync(resolve(dirname(xmlPath),name));
    if(sha(b)!==exact(a.getElementsByTagName('SHA256'),'SHA256').textContent||String(b.length)!==exact(a.getElementsByTagName('Bytes'),'Bytes').textContent)throw new Error(`El anexo fue alterado: ${name}`);
    count++;
  }
  if(wanted.size)throw new Error('Faltan anexos.');
  return {clave,referencias:refs.length,anexos:count,huellaCertificado:fingerprint,selloDeTiempo:'no',confianzaOficial:'no'};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  if(!process.argv[2]){console.error('Uso: node verify.mjs ruta/al/acta.xml [huella-SHA256-esperada]');process.exitCode=1;}
  else try{console.log(JSON.stringify(verifyBundle(process.argv[2],process.argv[3]),null,2));}catch(e){console.error(e.message);process.exitCode=1;}
}
