import {createHash, randomBytes} from 'node:crypto';
import {parse} from 'csv-parse/sync';
export const VERSION='1.0.0';
export const sha = b=>createHash('sha256').update(b).digest('hex');
export const money = n=>new Intl.NumberFormat('es-MX',{maximumFractionDigits:2}).format(n);
const DAY=86400000;
const normal = s=>String(s??'').normalize('NFD').replace(/\p{M}/gu,'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
const num = s=>/^[-+]?\d+(?:\.\d+)?$/.test(s??'') && Number.isFinite(Number(s)) ? Number(s) : null;
const inc=(m,k,d=1)=>m.set(k,(m.get(k)??0)+d);
const add=(m,k,v)=>{if(!m.has(k)) m.set(k,[]);m.get(k).push(v)};
const key=(...parts)=>JSON.stringify(parts);
const fields={a:['EJERCICIO','DEPENDENCIA','CLAVEUC','CODIGO_CONTRATO','NUMERO_PROCEDIMIENTO','TITULO_CONTRATO','TIPO_CONTRATACION','TIPO_PROCEDIMIENTO','IMPORTE_CONTRATO','MONEDA','PROVEEDOR_CONTRATISTA','FECHA_CELEBRACION'],b:['date','buyer_id','suppliers','tenderers','hasenquiries','method','amount','status','winner']};
function parseCSV(file, type) {
  const buf=file.bytes;
  let enc='utf8';
  try {new TextDecoder('utf-8',{fatal:true}).decode(buf)} catch {enc='latin1'}
  const convert = v=>enc==='latin1' && /[\u0080-\u009f]/.test(v)?new TextDecoder('windows-1252').decode(Buffer.from(v,enc)):v;
  let rows;
  try {
    rows=parse(buf,{encoding:enc,bom:enc==='utf8',info:true,skip_empty_lines:true,relax_column_count:true,max_record_size:1024*1024});
  } catch(e) {throw new Error(`CSV ${type.toUpperCase()}: formato no válido${e.lines?' cerca de la línea '+e.lines:''}. Usa un CSV separado por comas.`)}
  if(!rows.length || rows.length>300001) throw new Error('Cada CSV debe tener encabezados y como máximo 300,000 registros.');
  const head=rows.shift();
  const headers=head.record.map(v=>convert(v).trim());
  if(new Set(headers).size!==headers.length || !fields[type].every(f=>headers.includes(f))) throw new Error(`CSV ${type.toUpperCase()}: encabezados incompatibles. Revisa que cargaste el archivo en el campo correcto.`);
  const at=Object.fromEntries(headers.map((h,i)=>[h,i]));
  const source={name:file.name,sha256:sha(buf),encoding:enc==='utf8'?'UTF-8':'Windows-1252 (interpretación)',header:buf.subarray(0,head.info.bytes),count:rows.length,malformed:0};
  let pos=0,line=1;
  const advance=(end)=>{while(pos<end){const v=buf[pos++];if(v===13){if(pos<end&&buf[pos]===10)pos++;line++;}else if(v===10)line++;}};
  advance(head.info.bytes);
  const records=rows.map((entry,i)=>{
    const end=entry.info.bytes;
    // Offsets supplied by the parser are byte positions; physical line numbers are counted from original bytes.
    while(pos<end&&(buf[pos]===10||buf[pos]===13))advance(pos+(buf[pos]===13&&buf[pos+1]===10?2:1));
    const start=pos,first=line;
    advance(end);
    const last=Math.max(first,line-((buf[end-1]===10||buf[end-1]===13)?1:0));
    if(entry.record.length!==headers.length){source.malformed++;return null}
    return {bytes:buf.subarray(start,end),ordinal:i+1,first,last,get:(h)=>convert(entry.record[at[h]]??'').trim()};
  }).filter(Boolean);
  return {source,records};
}
function dateFull(v){
  const iso=/^(\d{4})-(\d{2})-(\d{2})(?:$|[ T])/.exec(v);
  const lat=/^(\d{2})\/(\d{2})\/(\d{4})$/.exec(v);
  if(!iso&&!lat)return null;
  const [y,m,d]=(iso?iso.slice(1):[lat[3],lat[2],lat[1]]).map(Number);
  if(y<1900||y>2200)return null;
  const t=Date.UTC(y,m-1,d); const chk=new Date(t);
  return chk.getUTCFullYear()===y&&chk.getUTCMonth()===m-1&&chk.getUTCDate()===d?t:null;
}
const locHint=d=>d.get('UBICACION')||d.get('ENTIDAD_FEDERATIVA')||d.get('ESTADO')||'';
const art217='Uso ilícito de atribuciones y facultades, art. 217 CPF. Hipótesis de revisión: verificar si el otorgamiento del contrato fue indebido conforme al régimen aplicable en su fecha.';
const evidenceLimit=15;
const pct=(a,b)=>b?Math.round(1000*a/b)/10:0;
function median(sorted) { const m=sorted.length>>1;return sorted.length%2?sorted[m]:(sorted[m-1]+sorted[m])/2; }
export function analyze(inputA,inputB, when=new Date()) {
  const a=parseCSV(inputA,'a'); const b=parseCSV(inputB,'b');
  const contracts=a.records.map(d=>({d,id:d.get('CODIGO_CONTRATO'), expediente:d.get('CODIGO_EXPEDIENTE'), proc:d.get('NUMERO_PROCEDIMIENTO'), inst:d.get('DEPENDENCIA'),uc:d.get('CLAVEUC'),year:d.get('EJERCICIO'), currency:d.get('MONEDA').toUpperCase(), amount:num(d.get('IMPORTE_CONTRATO')), title:d.get('TITULO_CONTRATO'), supplier:normal(d.get('PROVEEDOR_CONTRATISTA')),type:normal(d.get('TIPO_CONTRATACION')), method:normal(d.get('TIPO_PROCEDIMIENTO')), direct:/^adjudicacion directa\b/.test(normal(d.get('TIPO_PROCEDIMIENTO'))), status:normal(d.get('ESTATUS_CONTRATO')), signed:dateFull(d.get('FECHA_CELEBRACION')),loc:locHint(d)}));
  const counts=new Map(); for(const c of contracts)if(c.id)inc(counts,c.id);
  const good=contracts.filter(c=>c.id&&counts.get(c.id)===1&&c.inst&&c.uc&&/^\d{4}$/.test(c.year)&&c.currency&&c.amount>0&&c.type&&c.method&&!/cancel|anulad|rescind|revoc|desiert/.test(c.status));
  const cohorts=new Map(), units=new Map(), clusters=new Map();
  for(const c of good){
    const ins=normal(c.inst);
    add(cohorts,key(ins,c.uc,c.year,c.type,c.method,c.currency),c);
    if(c.supplier) add(units,key(ins,c.uc,c.year,c.type,c.method,c.currency),c);
    if(c.direct&&c.supplier&&c.proc&&c.signed!==null&&String(new Date(c.signed).getUTCFullYear())===c.year&&normal(c.title).length>=12) add(clusters,key(ins,c.uc,c.year,c.type,c.currency,c.supplier,normal(c.title)),c);
  }
  const flags=new Map();
  const flag=(c, kind, points, text, related=[])=>{if(!flags.has(c.id)) flags.set(c.id,{c,signals:new Map()}); if(!flags.get(c.id).signals.has(kind)) flags.get(c.id).signals.set(kind,{kind,points,text,related});};
  for(const group of cohorts.values()){
    if(group.length<12)continue;
    const values=group.map(c=>c.amount).sort((a,b)=>a-b);
    const log=values.map(n=>Math.log(n));const middle=median(log);
    const mad=median(log.map(n=>Math.abs(n-middle)).sort((a,b)=>a-b));
    const q95=values[Math.ceil(values.length*.95)-1];const med=median(values);
    if(mad<1e-8) continue;
    const examples=group.slice(0,5);
    for(const c of group){
      const z=.67448975*(Math.log(c.amount)-middle)/mad;
      if(c.amount>=q95 && c.amount>=med*2 && z>=3.5){
        const ordered=examples.filter(p=>p.id!==c.id).slice(0,4);
        flag(c,'Monto atípico',35,`Importe ${money(c.amount)} ${c.currency}, frente a mediana de ${money(med)} ${c.currency} y percentil 95 de ${money(q95)} (${group.length} registros de la misma dependencia, unidad, ejercicio, tipo, método y moneda). Desviación robusta sobre log-importes: ${z.toFixed(2)}; es rareza estadística, no sobreprecio.`,ordered);
      }
    }
  }
  for(const group of units.values()){
    const buyers=new Map();for(const c of group)add(buyers,c.supplier,c);
    if(group.length<12||buyers.size<3)continue;
    for(const peers of buyers.values()) if(peers.length>=5&&peers.length/group.length>=.5) for(const c of peers){
      const related=peers.slice(0,6).filter(p=>p.id!==c.id).slice(0,5);
      flag(c,'Concentración de proveedor',25,`El mismo nombre normalizado de proveedor aparece en ${peers.length} de ${group.length} contratos (${pct(peers.length,group.length)}%) con proveedor, en la misma dependencia, unidad, ejercicio, tipo, método y moneda; ${buyers.size} nombres distintos. Mide el archivo, no la cuota total de mercado ni una identidad fiscal confirmada.`,related);
    }
  }
  for(const group of clusters.values()){
    group.sort((x,y)=>x.signed-y.signed||x.d.ordinal-y.d.ordinal);
    for(let i=0;i<group.length;i++){
      const base=group[i]; const seen=new Set([base.proc]);const members=[base];
      for(let j=i+1;j<Math.min(group.length,i+200);j++){
        const c=group[j];if(c.signed-base.signed>30*DAY)break;
        if(!seen.has(c.proc)&&Math.max(c.amount,base.amount)/Math.min(c.amount,base.amount)<=1.25){seen.add(c.proc);members.push(c)}
      }
      if(members.length<3)continue;
      for(const c of members){
        if(flags.get(c.id)?.signals.has('Secuencia de adjudicaciones'))continue;
        flag(c,'Secuencia de adjudicaciones',60,`${members.length} procedimientos distintos con adjudicación directa, título normalizado idéntico, misma unidad, proveedor por nombre, ejercicio, tipo y moneda; fechas de celebración en ${Math.round((members.at(-1).signed-base.signed)/DAY)} días. Cada importe comparado con el primero difiere por un factor de hasta 1.25. Verificar si responden a una necesidad conjunta o son operaciones independientes. No se presume fraccionamiento.`,members.filter(p=>p.id!==c.id).slice(0,10));
      }
    }
  }
  const batch=randomBytes(4).toString('hex').toUpperCase();
  const year=new Intl.DateTimeFormat('es-MX',{year:'numeric',timeZone:'America/Mexico_City'}).format(when);
  const cases=[...flags.values()].map(({c,signals})=>{
    const list=[...signals.values()].sort((x,y)=>y.points-x.points);
    const weight=Math.min(100,list.reduce((n,s)=>n+s.points,0));
    const hypothesis=list.some(s=>s.kind==='Secuencia de adjudicaciones')?art217:null;
    const evidence=new Map([[c.id,{c,roles:new Set(['Registro principal'])}]]);
    for(const signal of list) for(const p of signal.related){if(!evidence.has(p.id))evidence.set(p.id,{c:p,roles:new Set()});evidence.get(p.id).roles.add(signal.kind)}
    return {contract:c.id,title:c.title,proc:c.proc,expediente:c.expediente,institution:c.inst,uc:c.uc,year:c.year,location:c.loc||'No disponible en el CSV',person:'No identificada; requiere revisión humana',amount:c.amount,currency:c.currency,weight,hypothesis,signals:list.map(({kind,text})=>({kind,text})),evidence:[...evidence.values()].slice(0,evidenceLimit),evidenceAvailable:evidence.size};
  }).sort((x,y)=>y.weight-x.weight||x.evidence[0].c.d.ordinal-y.evidence[0].c.d.ordinal);
  cases.forEach((c,i)=>{c.id=`DEN-${year}-${batch}-${String(i+1).padStart(4,'0')}`;c.created=when.toISOString()});
  let missingYear=0, zeroAmounts=0, negatives=0,bDirect=0,bExcluded=0,distinctInput=0;
  const duplicates=new Set(), bulkMap=new Map();
  for(const d of b.records){
    if(dateFull(d.get('date'))===null)missingYear++;
    if(num(d.get('amount'))===0)zeroAmounts++;
    const tender=num(d.get('tenderers'));if(tender!==null&&tender<0)negatives++;
    if(d.get('method').toLowerCase()!=='direct')continue;
    bDirect++;
    const buyer=d.get('buyer_id'),winner=d.get('winner');
    if(!buyer||!winner||tender===null||tender<0||d.get('status').toLowerCase()!=='complete'){bExcluded++;continue;}
    const signature=JSON.stringify(fields.b.map(f=>d.get(f)));
    if(duplicates.has(signature))continue;
    duplicates.add(signature);distinctInput++;
    if(!bulkMap.has(buyer))bulkMap.set(buyer,{n:0,counts:new Map()});
    const row=bulkMap.get(buyer);row.n++;inc(row.counts,winner);
  }
  const bulk=[...bulkMap].filter(([,r])=>r.n>=25&&r.counts.size>=3).map(([buyer,r])=>{
    const top=Math.max(...r.counts.values());return {buyer,count:r.n,top,share:pct(top,r.n)};
  }).filter(x=>x.share>=40).sort((x,y)=>y.share-x.share||y.count-x.count).slice(0,15);
  const profile={a:{name:a.source.name,sha256:a.source.sha256,rows:a.source.count,malformed:a.source.malformed,direct:contracts.filter(c=>c.direct).length,valid:good.length,duplicated:contracts.filter(c=>c.id&&counts.get(c.id)>1).length,missingDate:contracts.filter(c=>c.signed===null).length,years:[...new Set(contracts.map(c=>c.year).filter(y=>/^\d{4}$/.test(y)))].sort()},b:{name:b.source.name,sha256:b.source.sha256,rows:b.source.count,malformed:b.source.malformed,direct:bDirect,missingYear,zeroAmounts,negatives,eligible:distinctInput,excluded:bExcluded,context:bulk},total:cases.length,article217:cases.filter(c=>c.hypothesis).length,version:VERSION};
  return {sources:{a:a.source,b:b.source},cases,profile};
}
export function publicCase(c){const {evidence,evidenceAvailable,...rest}=c; return {...rest,evidenceRows:evidence.length,evidenceAvailable};}
