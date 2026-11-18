import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {basename} from 'node:path';
import Busboy from 'busboy';
import {analyze,publicCase} from './analysis.mjs';
import {makeSigner,makeFiles,batchZip} from './documents.mjs';

const host='127.0.0.1';
const port=Number(process.env.PORT??4173);
const lifetime=30*60*1000;
const sessions=new Map();
const sweep=()=>{for(const [token,session] of sessions)if(session.expires<Date.now())sessions.delete(token)};
setInterval(sweep,60000).unref();
const assets=Object.fromEntries(await Promise.all(Object.entries({'/':['index.html','text/html'],'/app.js':['app.js','application/javascript'],'/style.css':['style.css','text/css']}).map(async ([k,[f,mime]])=>[k,{body:await readFile(new URL(`./public/${f}`,import.meta.url)),mime}])));
const types={xml:'application/xml',pdf:'application/pdf','evidencias.json':'application/json',zip:'application/zip'};
const send=(res,body,type,code=200)=>{res.statusCode=code;res.setHeader('Content-Type',type);res.end(body)};
const json=(res,o,n)=>send(res,JSON.stringify(o),'application/json; charset=utf-8',n);
const download=(res,f,ext,b)=>{res.setHeader('Content-Disposition',`attachment; filename="${f}"`);send(res,b,types[ext]);};
const bad=(message,status=400)=>Object.assign(new Error(message),{status});
let busy=false;
function upload(req){
  return new Promise((resolve,reject)=>{
    const files=Object.create(null),fields=Object.create(null);let failure;
    const report=(m)=>{failure??=bad(m)};
    let parser;
    try {parser=Busboy({headers:req.headers,defParamCharset:'utf8',limits:{fileSize:25*1024*1024,files:4,fields:1,parts:8,fieldSize:1024,headerPairs:30}})} catch {return reject(bad('Carga los archivos mediante el formulario.'))}
    parser.on('file',(field,stream,info)=>{
      if(!['a','b','key','cert'].includes(field)||Object.hasOwn(files,field)){report('Campo de archivo desconocido o repetido.');stream.resume();return;}
      const chunks=[];let total=0;
      files[field]=null;
      stream.on('data',b=>{total+=b.length;if((field==='key'||field==='cert')&&total>256*1024)report('El archivo .KEY o .CER excede 256 KB.');if(!failure)chunks.push(b);});
      stream.on('limit',()=>report('Cada CSV admite un máximo de 25 MB.'));
      stream.on('error',()=>report('La carga se interrumpió.'));
      stream.on('end',()=>{if(!failure)files[field]={name:basename(info.filename||field).replace(/[\u0000-\u001f\u007f]/g,'').slice(0,210),bytes:Buffer.concat(chunks)}});
    });
    parser.on('field',(field,value,info)=>{if(field!=='password'||info.valueTruncated)report('Campo de firma inválido.');else fields.password=value});
    for(const e of ['filesLimit','fieldsLimit','partsLimit'])parser.on(e,()=>report('El formulario contiene campos de más.'));
    parser.on('error',()=>reject(bad('No se pudo leer la carga.')));
    parser.on('close',()=>failure?reject(failure):resolve({files,fields}));
    req.on('aborted',()=>{parser.destroy();reject(bad('La carga se interrumpió.'));});
    req.on('error',()=>{parser.destroy();reject(bad('No se pudo leer la solicitud.'));});
    req.pipe(parser);
  });
}
async function readSmallJson(req){
  const chunks=[];let size=0;
  for await(const b of req){size+=b.length;if(size>4096)throw bad('Selección demasiado grande.');chunks.push(b);}
  try {return JSON.parse(Buffer.concat(chunks).toString());} catch {throw bad('Selección no válida.');}
}
const server=http.createServer({requestTimeout:120000},async(req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Content-Security-Policy',"default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  try {
    const authority=`${host}:${server.address().port}`;
    if(req.headers.host!==authority)throw bad('Abre la dirección 127.0.0.1 indicada por el servidor.',403);
    const url=new URL(req.url,`http://${authority}`);const route=url.pathname;
    if(req.method==='POST'&&req.headers.origin!==`http://${authority}`)throw bad('Origen no permitido.',403);
    if(req.headers['sec-fetch-site']==='cross-site')throw bad('Solicitud externa bloqueada.',403);
    if(req.method==='GET'&&Object.hasOwn(assets,route)){const o=assets[route];return send(res,o.body,o.mime+'; charset=utf-8');}
    if(req.method==='GET'&&route==='/favicon.ico'){res.statusCode=204;return res.end();}
    if(req.method==='POST'&&route==='/api/analyze'){
      if(busy)throw bad('Ya hay un análisis en curso. Intenta en unos segundos.',429);
      busy=true;
      try {
        const {files,fields}=await upload(req);
        let signer, result;
        try {
          if(!files.a?.bytes.length||!files.b?.bytes.length)throw bad('Selecciona ambos CSV.');
          if(!!files.key!==!!files.cert||(!files.key&&fields.password))throw bad('Carga juntos la .KEY y el .CER de prueba, o usa el certificado automático.');
          result=analyze(files.a,files.b);
          signer=await makeSigner(files.key?{key:files.key.bytes,cert:files.cert.bytes,password:fields.password??''}:null);
        } finally {files.key?.bytes.fill(0);delete fields.password;}
        const token=randomBytes(24).toString('hex');const expires=Date.now()+lifetime;
        sweep();while(sessions.size>=4)sessions.delete(sessions.keys().next().value);
        sessions.set(token,{signer,sources:result.sources,byId:new Map(result.cases.map(c=>[c.id,c])),cache:new Map(),expires});
        return json(res,{token,profile:result.profile,cases:result.cases.map(publicCase),signer:signer.mode});
      } finally {busy=false;}
    }
    const match=/^\/api\/run\/([a-f\d]{48})\/(reset|batch|DEN-\d{4}-[A-F\d]{8}-\d+\.(?:pdf|xml|evidencias\.json))$/.exec(route);
    if(match){
      sweep();const session=sessions.get(match[1]);if(!session)throw bad('La corrida expiró. Vuelve a cargar los dos CSV.',404);
      const op=match[2];
      if(req.method==='POST'&&op==='reset'){sessions.delete(match[1]);return json(res,{ok:true});}
      if(req.method==='POST'&&op==='batch'){
        const input=await readSmallJson(req);const ids=input?.ids;
        if(!Array.isArray(ids)||ids.length<1||ids.length>10||new Set(ids).size!==ids.length||!ids.every(i=>session.byId.has(i)))throw bad('Selecciona de 1 a 10 actas válidas.');
        return download(res,'DenuncIA-actas-demo.zip','zip',await batchZip(ids.map(i=>session.byId.get(i)),session));
      }
      if(req.method==='GET'&&op.includes('.')){
        const i=op.indexOf('.');const c=session.byId.get(op.slice(0,i));if(!c)throw bad('Acta no encontrada.',404);
        const ext=op.slice(i+1);return download(res,op,ext,(await makeFiles(c,session))[ext]);
      }
    }
    throw bad('No se encontró ese recurso.',404);
  } catch(e){ if(!res.headersSent)json(res,{error:e.message||'Error interno.'},e.status??400);else res.end(); }
});
server.on('error',e=>{console.error(`No se pudo iniciar la demo (${e.code??'error'}). Usa un puerto local libre.`);process.exitCode=1});
server.listen(port,host,()=>console.log(`DenuncIA demo local: http://${host}:${server.address().port}/\nNo cierres esta terminal mientras uses la demo.`));
