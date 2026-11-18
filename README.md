# DenuncIA | demo local de revisión de contrataciones

**Prototipo independiente, no afiliado a la Plataforma Digital Nacional ni al Sistema Nacional Anticorrupción.** No envía documentos, no identifica personas responsables y no determina delitos. Un acta es un borrador de triaje, no un escrito presentado. El puntaje es una prioridad heurística, no una probabilidad.

## Probarlo

1. Instala [Node.js](https://nodejs.org/) 22.12 o posterior. Descomprime el proyecto y abre una terminal en su carpeta.
2. Ejecuta `npm ci` (descarga dependencias una sola vez) y luego `npm start`.
3. Abre **http://127.0.0.1:4173/** en Chrome u otro navegador. Deja la terminal abierta. Selecciona tus CSV en A y B, y presiona **Analizar ambos CSV**. Los CSV originales no se incluyen en el proyecto.
4. Abre **Ver acta** para descargar XML, PDF y anexo JSON. O selecciona hasta diez filas y descarga un ZIP. La demo admite 25 MB y 300,000 registros por CSV. Si A y B se intercambian o tienen otros encabezados, el sistema avisa.
5. **Borrar corrida** elimina la sesión del servidor local. También se elimina al cerrar el servidor o 30 minutos después de crearla. Los archivos que descargues sí permanecen. No abras la aplicación como servicio público ni cambies la dirección de escucha.

En macOS/Linux, si el puerto está ocupado: `PORT=4317 npm start`. En PowerShell: `$env:PORT=4317; npm start`. Usa la dirección que muestra la terminal. No hay conexión de la app a servicios externos ni guardado persistente de sus cargas.

## Firma y verificación

Por defecto la demo crea una llave RSA efímera y un certificado X.509 autofirmado. También puedes usar tu propio par **autofirmado de laboratorio**: `.KEY` en PEM o PKCS#8 DER cifrada, `.CER` X.509 DER/PEM y contraseña de prueba. No cargues e.firma real ni descargues llaves privadas del SAT. La interfaz no acepta credenciales emitidas por una autoridad. No se exporta la llave ni se incluye en los ZIP.

- El XML contiene una firma envolvente (`enveloped`) XAdES-BES de prueba, RSA/SHA-256, con referencias al documento y a `SignedProperties`. La hora declarada no es un sello de tiempo acreditado. La firma autofirmada no acredita identidad ni autorización oficial. No se ha probado la aceptación por un receptor institucional.
- El PDF es de visualización y **no contiene una firma PDF**. Su integridad, igual que la del JSON de evidencias, se vincula al XML mediante SHA-256.
- El anexo contiene el encabezado y los registros originales en Base64, con número de registro, líneas físicas, rol y hash. Los comparables son una muestra, no la cohorte completa. Pueden aparecer nombres u otros valores públicos tal como venían en el origen; no son personas denunciadas.
- Para verificar un paquete descomprimido con una segunda implementación de XMLDSig: `node verify.mjs ruta/al/acta.xml`. Un segundo argumento opcional fija la huella SHA-256 esperada del certificado. El XML, PDF y anexo deben estar en la misma carpeta. El verificador comprueba firma, referencias, certificado autofirmado y hashes adjuntos, no la veracidad de los datos ni la aceptación oficial. Conserva también el CSV original si necesitas reproducir la corrida.
- `npm test` prueba firma, alteraciones, anexos y credenciales de laboratorio usando datos sintéticos.

## Qué analiza

- **A / Contratos.** Excluye códigos de contrato repetidos y filas no elegibles. Aprende un centro y dispersión robusta de los log-importes para cada cohorte de dependencia, unidad, ejercicio, tipo, método y moneda con al menos 12 contratos. Señala si un monto alcanza el percentil 95, es al menos el doble de la mediana y se desvía 3.5 unidades robustas o más (35 puntos). No es un modelo de precios. Una concentración por nombre de proveedor se señala cuando hay al menos 5 contratos, al menos la mitad de los registros con proveedor y tres nombres distintos en la cohorte (25 puntos). Usa nombres normalizados como aproximación, no identidad confirmada. Una secuencia requiere al menos tres procedimientos directos distintos, título normalizado, unidad y proveedor iguales, fechas de celebración en 30 días e importes con factor máximo 1.25 frente al primero (60 puntos). La asignación de puntos es heurística y se limita a 100. Las secuencias generan una hipótesis documental, no corroborada, para revisar el art. 217. Los otros patrones no se etiquetan con un delito.
- **B / Contrataciones abiertas.** Presenta métricas de calidad y concentración exploratoria por comprador. Para esto elimina combinaciones idénticas de los nueve campos y excluye datos no elegibles; no confunde estas combinaciones con contratos únicos. No usa el importe para comparar porque falta moneda y gran parte de los importes vienen en cero. Sin identificador compartido ni año no se hace cruce contractual ni se atribuye una anomalía concreta a un ganador de B.
- **Los demás delitos.** El CSV no observa sobornos, amenazas, patrimonio, autorización formal, relaciones personales, desvío efectivo o el resto de elementos necesarios para clasificarlos. No se generan etiquetas para los demás artículos. Ubicación y nombre de la persona se dejan sin identificar si no hay una fuente que los sustente; un responsable de unidad o proveedor no se convierte en denunciado.

## Resultados de la corrida incluida por separado

El archivo A contiene 4,498 registros de 2013 a 2019, de los cuales 4,495 son adjudicaciones directas. Dos filas con el mismo código de contrato se excluyen y 1,674 filas no tienen fecha de celebración válida. El B contiene 97,843 registros sin fecha completa, 95,826 importes en cero y 13,247 conteos de licitantes negativos. Se encontraron **nueve montos atípicos y ninguna hipótesis penal**. Los nueve borradores se incluyen en un ZIP independiente. Son prioridades de revisión, no expedientes de ilícitos.

## Siguiente versión recomendada

1. Recuperar OCDS/OCID, expediente, monedas, año y registros originales de avisos, ofertas, fallos, excepciones, contratos, modificaciones y pagos. Vincular solo con identificadores verificados y versionar las fuentes por fecha. Incorporar catálogos de objetos, cantidades y precios unitarios; comparar productos y condiciones equivalentes.
2. Hacer una matriz por artículo del [Código Penal Federal](https://www.diputados.gob.mx/LeyesBiblio/pdf/CPF.pdf), con la normativa aplicable a la fecha del procedimiento, datos de soporte, explicaciones alternativas y criterios de abstención. Una revisión experta documenta lo que falta y establece autoridad y canal competentes; no hay envío automático.
3. Reunir revisiones históricas como etiquetas de **hallazgos auditables**, no de culpabilidad. Antes de un modelo más complejo, medir precisión en los primeros K casos, falsas alarmas por entidad y tipo de contrato, y estabilidad en años reservados. Comparar un Isolation Forest explicable por características con el baseline robusto. Incorporar monitoreo de cambios, protección de datos y registro de cambios editoriales.
4. Si hay un piloto oficial, acordar con el receptor el esquema, perfil de firma, certificado autorizado, política de sellado, revocación y custodia de llave. Validar con sus herramientas. Asegurar revisión y autorización humana antes de firmar o presentar un escrito formal.
