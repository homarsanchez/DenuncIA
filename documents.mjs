import {createPrivateKey,webcrypto,X509Certificate} from 'node:crypto';
import 'reflect-metadata';
import {X509CertificateGenerator,BasicConstraintsExtension,KeyUsageFlags,KeyUsagesExtension} from '@peculiar/x509';
import * as x from 'xadesjs';
import {XMLSerializer,DOMParser,DOMImplementation} from '@xmldom/xmldom';
import xpath from 'xpath';
import PDFDocument from 'pdfkit';
import AdmZip from 'adm-zip';
import {VERSION,sha,money} from './analysis.mjs';
x.setNodeDependencies({XMLSerializer,DOMParser,DOMImplementation,xpath});
x.Application.setEngine('node',webcrypto);
const algo={name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'};
export const DS='http://www.w3.org/2000/09/xmldsig#';
export const XA='http://uri.etsi.org/01903/v1.3.2#';
export const issuer='Sistema DenuncIA (Inteligencia Artificial) · demo independiente';
export const noAuthority='Ninguna. No es un documento de la Plataforma Digital Nacional ni del Sistema Nacional Anticorrupción.';
const disclaimer='Borrador de triaje. No acredita un delito ni identifica responsables. No está presentado ante ninguna autoridad.';
const classification=c=>c.hypothesis?'Art. 217 CPF (hipótesis no corroborada)':'Sin clasificación penal';
const description=c=>c.hypothesis??'Anomalía estadística para revisión documental. Los registros disponibles no permiten proponer un delito del catálogo.';
const next='Cotejar el anuncio y el expediente original; verificar objeto, alcance, cotizaciones, justificación del procedimiento, normativa vigente en la fecha y posibles errores de registro. No atribuir autoría sin soporte independiente.';
export async function makeSigner(input){
  let pub,priv;
  if(input){
    try {pub=new X509Certificate(input.cert);} catch {throw new Error('El .CER de prueba no tiene formato X.509 DER o PEM.')}
    if(pub.subject!==pub.issuer||!pub.verify(pub.publicKey))throw new Error('El prototipo solo admite certificados autofirmados de prueba; no admite e.firma del SAT.');
    const current=Date.now();
    if(Date.parse(pub.validFrom)>current||Date.parse(pub.validTo)<current)throw new Error('El certificado de prueba no está vigente.');
    try {
      priv=input.key.subarray(0,28).toString().startsWith('-----BEGIN ')?createPrivateKey({key:input.key,passphrase:input.password}):createPrivateKey({key:input.key,format:'der',type:'pkcs8',passphrase:input.password});
    } catch {throw new Error('No se pudo abrir la .KEY de prueba (RSA PKCS#8 DER o PEM). Revisa el formato y contraseña.')}
  } else {
    const keys=await webcrypto.subtle.generateKey({...algo,modulusLength:2048,publicExponent:new Uint8Array([1,0,1])},false,['sign','verify']);
    const now=Date.now();
    const cert=await X509CertificateGenerator.createSelfSigned({name:'CN=DenuncIA Demo No Oficial',keys,signingAlgorithm:algo,notBefore:new Date(now-60000),notAfter:new Date(now+30*86400000),extensions:[new BasicConstraintsExtension(false,undefined,true),new KeyUsagesExtension(KeyUsageFlags.digitalSignature,true)]},webcrypto);
    pub=new X509Certificate(Buffer.from(cert.rawData));
    return {privateKey:keys.privateKey,certificate:pub.raw.toString('base64'),fingerprint:pub.fingerprint256.replaceAll(':','').toLowerCase(),mode:'Autofirmado efímero de prueba'};
  }
  if(!pub.checkPrivateKey(priv)||priv.asymmetricKeyType!=='rsa'||priv.asymmetricKeyDetails.modulusLength<2048)throw new Error('La llave y el certificado deben corresponder y usar RSA de al menos 2048 bits.');
  const der=priv.export({format:'der',type:'pkcs8'});
  try {
    const privateKey=await webcrypto.subtle.importKey('pkcs8',der,algo,false,['sign']);
    return {privateKey,certificate:pub.raw.toString('base64'),fingerprint:pub.fingerprint256.replaceAll(':','').toLowerCase(),mode:input?'Autofirmado local de prueba':'Autofirmado efímero de prueba'};
  } finally {der.fill(0)}
}
const xmlText = v=>String(v??'').replace(/\r\n?|\n/g,'\n').replace(/[^\u0009\u000a\u000d\u0020-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/gu,'�').replace(/[&<>"'\r]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;','\r':'&#13;'})[c]);
const tag=(t,v)=>`<${t}>${xmlText(v)}</${t}>`;
const fileDigest=(name,bytes)=>({name,sha256:sha(bytes),size:bytes.length});
export function evidenceFor(c,source){
  return {formato:'denuncia-dataset-evidence/1',clave:c.id,origen:{archivo:source.name,sha256Archivo:source.sha256,codificacion:source.encoding,encabezadoBase64:source.header.toString('base64')},registros:c.evidence.map(({c:r,roles})=>({orden:r.d.ordinal,lineaInicial:r.d.first,lineaFinal:r.d.last,contrato:r.id,procedimiento:r.proc,rol:[...roles],sha256:sha(r.d.bytes),registroCSVBase64:r.d.bytes.toString('base64')})),nota:'Los registros son bytes del CSV original codificados en Base64. Los comparables son una selección, no toda la cohorte.'};
}
async function signedXml(c,session,files){
  const {sources,signer}=session;
  const xml=x.Parse(`<ActaDenuncIA version="1.0" modo="demo-local">${tag('ClaveActa',c.id)}${tag('FechaGeneracion',c.created)}${tag('Aviso',disclaimer)}<Resumen>${tag('Denunciado',c.person)}${tag('Institucion',c.institution)}${tag('Ubicacion',c.location)}${tag('OtrasReferencias',`Contrato ${c.contract}; procedimiento ${c.proc||'no disponible'}; expediente ${c.expediente||'no disponible'}; unidad ${c.uc}; ejercicio ${c.year}.`)}${tag('Clasificacion',classification(c))}${tag('Descripcion',description(c))}${tag('Objeto',c.title)}${tag('Importe',c.amount)}${tag('Moneda',c.currency)}${tag('PuntajeTriageNoProbabilidad',c.weight)}</Resumen><Evidencias><Narracion>${c.signals.map(s=>`<Patron>${tag('Nombre',s.kind)}${tag('Hallazgo',s.text)}</Patron>`).join('')}${tag('SiguientePaso',next)}</Narracion><Fuentes>${[sources.a,sources.b].map((s,i)=>`<Fuente>${tag('Nombre',s.name)}${tag('SHA256',s.sha256)}${tag('Uso',i===0?'Registros del expediente':'Contexto agregado; sin cruce a esta adquisición')}</Fuente>`).join('')}</Fuentes><ArchivosAdjuntos>${files.map(f=>`<Archivo>${tag('Nombre',f.name)}${tag('SHA256',f.sha256)}${tag('Bytes',f.size)}</Archivo>`).join('')}</ArchivosAdjuntos>${tag('RegistrosAdjuntos',c.evidence.length)}${tag('VersionDetector',VERSION)}</Evidencias>${tag('InstitucionFirmante',noAuthority)}${tag('EmisorTecnico',issuer)}${tag('Credencial',signer.mode)}${tag('HuellaCertificadoSHA256',signer.fingerprint)}</ActaDenuncIA>`);
  const signed=new x.SignedXml();
  await signed.Sign(algo,signer.privateKey,xml,{x509:[signer.certificate],signingCertificate:signer.certificate,signingTime:{value:new Date(c.created)},references:[{uri:'',hash:'SHA-256',transforms:['enveloped']}]});
  const result=signed.toString();
  if(!await verifyXml(result))throw new Error('La validación de la firma generada no pasó. No se emitió el XML.');
  return Buffer.from('<?xml version="1.0" encoding="UTF-8"?>\n'+result);
}
export async function verifyXml(content){
  try {
    const parsed=x.Parse(content.toString());
    const signatures=parsed.getElementsByTagNameNS(DS,'Signature');
    const properties=parsed.getElementsByTagNameNS(XA,'SignedProperties');
    if(signatures.length!==1||properties.length!==1)return false;
    const xml=new x.SignedXml(parsed);xml.LoadXml(signatures[0]);
    return await xml.Verify();
  } catch {return false;}
}
function renderPdf(c, evidence, signer){
  return new Promise((resolve,reject)=>{
    const doc=new PDFDocument({size:'A4',margin:54,info:{Title:`${c.id} | Acta de revisión`,Author:'DenuncIA Demo Local',CreationDate:new Date(c.created),ModDate:new Date(c.created)},bufferPages:true});
    const buf=[];doc.on('data',b=>buf.push(b));doc.on('error',reject);doc.on('end',()=>resolve(Buffer.concat(buf)));
    const box=(text)=>{doc.font('Helvetica-Bold').fontSize(10).fillColor('#a24418').text(text,{lineGap:2});doc.moveDown(.65)};
    const title=(text)=>{doc.moveDown(.65);doc.font('Helvetica-Bold').fontSize(15).fillColor('#114f48').text(text);doc.moveDown(.3)};
    const line=(label,text)=>{doc.font('Helvetica-Bold').fontSize(10).fillColor('#172c30').text(`${label}: `,{continued:true});doc.font('Helvetica').text(String(text),{lineGap:2});doc.moveDown(.21)};
    box('DENUNCIA / DEMO LOCAL / NO OFICIAL');
    doc.font('Helvetica-Bold').fontSize(28).fillColor('#132c30').text('Acta de revisión');
    doc.font('Helvetica').fontSize(13).fillColor('#114f48').text(c.id);doc.moveDown(.8);box(disclaimer);
    title('01 / Resumen');
    line('Denunciado',c.person);line('Institución',c.institution);line('Ubicación',c.location);line('Objeto',c.title||'No disponible');line('Otras referencias',`Contrato ${c.contract}; procedimiento ${c.proc||'no disponible'}; expediente ${c.expediente||'no disponible'}; unidad ${c.uc}; ejercicio ${c.year}.`);
    line('Importe observado',`${money(c.amount)} ${c.currency}`);line('Clasificación',classification(c));line('Descripción',description(c));line('Puntaje de triaje',`${c.weight}/100; no es una probabilidad de delito`);
    title('02 / Evidencias y verificación');
    for(const s of c.signals)line(s.kind,s.text);
    line('Siguiente paso',next);line('Anexo',`${evidence.name}; ${c.evidence.length} registros del CSV original. Comparables de muestra, no cohorte completa.`);line('SHA-256 del anexo',evidence.sha256);
    title('03 / Firma y alcance');
    line('Institución firmante',noAuthority);line('Emisor técnico de prueba',issuer);line('Certificado',`${signer.mode}; huella SHA-256 ${signer.fingerprint}`);line('Fecha UTC',c.created);line('Firma electrónica','La firma XAdES-BES está en el XML. Este PDF es una copia de visualización, vinculada por hash al XML; no contiene una firma PDF.');
    doc.end();
  });
}
export async function makeFiles(c,session){
  if(!session.cache.has(c.id)){
    const promise=(async()=>{
      const annex=Buffer.from(JSON.stringify(evidenceFor(c,session.sources.a),null,2));
      const evidence=fileDigest(`${c.id}.evidencias.json`,annex);
      const pdf=await renderPdf(c,evidence,session.signer);
      const xml=await signedXml(c,session,[evidence,fileDigest(`${c.id}.pdf`,pdf)]);
      return {'evidencias.json':annex,pdf,xml};
    })();
    session.cache.set(c.id,promise);
    promise.catch(()=>session.cache.delete(c.id));
    if(session.cache.size>40) session.cache.delete(session.cache.keys().next().value);
  }
  return session.cache.get(c.id);
}
export async function batchZip(cases,session){
  const zip=new AdmZip();
  for(const c of cases){const files=await makeFiles(c,session);for(const [ext,buf] of Object.entries(files))zip.addFile(`${c.id}/${c.id}.${ext}`,buf);}
  zip.addFile('LEER-PRIMERO.txt',Buffer.from(`${issuer}\n${disclaimer}\nXAdES-BES con certificado autofirmado de prueba. El XML incluye un SHA-256 del PDF y del JSON de registros.\n`));
  return zip.toBuffer();
}
