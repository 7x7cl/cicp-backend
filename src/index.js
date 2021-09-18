var express = require("express")
var serviceAccount = require("../tokens/firebasekey.json")
var credentialsGoogle = require("../tokens/googlesdk.json")
var jsonParser = express.json()
var PouchDB = require("pouchdb")
PouchDB.plugin(require('pouchdb-find'));
var admin = require("firebase-admin")
var axios = require("axios")
var axiosCookieJarSupport = require("axios-cookiejar-support").default
var tough = require("tough-cookie")
var { google } = require("googleapis")
var cors = require('cors')
var path = require('path')
var ExpressPouchDB = require('express-pouchdb')

let PouchDBServer = PouchDB.defaults({ prefix: path.resolve(__dirname, "../DB/") + "/" })

function generateToken(n) {
    var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var token = '';
    for (var i = 0; i < n; i++) {
        token += chars[Math.floor(Math.random() * chars.length)];
    }
    return token;
}

async function obtenerIdentidad(token) {
    let identidad;
    try {
        identidad = await admin
            .auth()
            .verifyIdToken(token);
        if (!identidad.permisos) identidad.permisos = []

        if (!identidad.email_verified) {
            throw { error: "Tu correo no está verificado" };
        }
    } catch (error) {
        throw { error: "No se pudo verificar la identidad", o: error };
    }
    let usuarioautenticados;
    try {
        usuarioautenticados = (await usuarios.find({
            selector: {
                correos: {
                    $elemMatch: identidad.email
                }
            }
        })).docs;

    } catch (error) {
        throw { error: "Ocurrio un error en la búsqueda" };
    }


    if (usuarioautenticados.length == 1) {
        usuarioautenticados[0]['correologeado'] = identidad.email
        return usuarioautenticados[0];
    } else if (usuarioautenticados.length == 0) {
        throw { error: "Usuario no encontrado" }
    } else {
        throw { error: "Usuario duplicado, su caso a sido informado automaticamente a soporte técnico" }
    }
}

const auth = new google.auth.GoogleAuth({
    credentials: credentialsGoogle,
    scopes: ['https://www.googleapis.com/auth/admin.directory.user'],
});

axiosCookieJarSupport(axios);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://cicp-olmue.firebaseio.com"
});

const app = express();
app.use(cors())

let usuarios = new PouchDBServer("Usuarios");
let configdb = new PouchDBServer("Config");


app.use(async function (req, res, next) {
    try {
        let configuracion = await configdb.get("configuracion")
        res.set('VersionApi', `${configuracion.version}`)
        if (configuracion.modomantenimiento) {
            // return res.status(503).send({ error: "El servidor esta en modo de mantenimiento" });
        }
    } catch (error) {
    }
    next();
});


app.post('/yo', jsonParser, async (req, res) => {

    if (!req.body.id_token) {
        res.status(400).send({ error: "Falta el id_token en la solicitud" });
        return;
    }

    try {
        let identidad = await obtenerIdentidad(req.body.id_token);
        res.send(identidad)
    } catch (error) {
        res.status(401).send(error)
    }
});

app.post('/claves/encontrarrun', jsonParser, async (req, res) => {

    if (!req.body.run) {
        return res.status(400).send({ error: "Falta el R.U.N. en la solicitud" });
    }
    let usuario;
    try {
        usuario = await usuarios.get(req.body.run);
    } catch (error) {
        return res.send({ tipo: "No Registrado" })
    }

    if (usuario.tipo == "Administrador") return res.status(400).send({ error: "No se permite esta acción en el adminstrador de la red" })

    res.send({ tipo: usuario.tipo })

});

app.post('/claves/obtenercaptcha', jsonParser, async (req, res) => {
    try {
        const cookieJar = new tough.CookieJar();
        let result = (await axios
            .get('https://portal.sidiv.registrocivil.cl/usuarios-portal/pages/DocumentRequestStatus.xhtml', {
                jar: cookieJar,
                timeout: 1000,
                withCredentials: true,
            })).data

        var javax = result.substring(
            result.indexOf("s.ViewState\" id=\"javax.faces.ViewState\" value=\"") + "s.ViewState\" id=\"javax.faces.ViewState\" value=\"".length,
            result.lastIndexOf("\" autoco")
        );
        var cookies =
            cookieJar.getCookiesSync("https://portal.sidiv.registrocivil.cl/usuarios-portal/pages/DocumentRequestStatus.xhtml")
        var SESSIONID = cookies[cookies.findIndex((e) => e.key == "JSESSIONID")].value
        let img = Buffer.from((await axios
            .get(`https://portal.sidiv.registrocivil.cl/usuarios-portal/faces/myFacesExtensionResource/org.apache.myfaces.custom.captcha.CAPTCHARenderer/15923103/;jsessionid=${SESSIONID}}?captchaSessionKeyName=mySessionKeyName`, {
                jar: cookieJar,
                timeout: 2000,
                responseType: 'arraybuffer',
                withCredentials: true,
            })).data, 'binary').toString('base64')
        res.send({
            code: 200,
            respuesta: "",
            javax: javax,
            cookies: Buffer.from(JSON.stringify(cookieJar.toJSON())).toString("base64"),
            captcha: `data:image/jpeg;base64, ${img}`
        })
    } catch (error) {
        res.status(500).send({ error: "No se pudo obtener el captcha" })
    }
});

app.post('/claves/verificaridentidad', jsonParser, async (req, res) => {
    if (!req.body.run) return res.status(400).send({ error: "No se encontro run en la solicitud" })
    let identidad
    try {
        identidad = await usuarios.get(req.body.run);
    } catch (error) {
        return res.status(404).send({ error: "Error al encontrar autorización" })
    }
    if (identidad.tipo == "Administrador") return res.status(400).send({ error: "No se permite esta acción en el adminstrador de la red" })
    let tokenstemporales = new PouchDBServer("TokensTemporales")
    let token;
    if (req.body.token) {
        try {
            let tokentemp = await tokenstemporales.get(req.body.token)
            if (tokentemp.run != req.body.run) return res.status(400).send({ error: "El token no coincide con el R.U.N." })
            if (tokentemp.time < Date.now()) return res.status(400).send({ error: "El token esta expirado" })
            token = {
                _id: tokentemp._id,
                time: tokentemp.time,
                run: req.body.run
            }
        } catch (error) {
            return res.status(400).send({ error: "El token no sirve o esta expirado" })
        }
    } else {
        if (!req.body.captcha.respuesta) return res.status(400).send({ error: "No se encontro captcha en la solicitud" })
        if (!req.body.ndocumento) return res.status(400).send({ error: "No se encontro número de documento en la solicitud" })
        if (!req.body.captcha.javax) return res.status(400).send({ error: "No se encontro javax en la solicitud" })
        if (!req.body.captcha.cookies) return res.status(400).send({ error: "No se encontro cookies en la solicitud" })

        let result = "";
        try {
            const cookieJar = tough.CookieJar.fromJSON(JSON.parse(Buffer.from(req.body.captcha.cookies, 'base64').toString("ascii")));
            result = (await axios({
                url: 'https://portal.sidiv.registrocivil.cl/usuarios-portal/pages/DocumentRequestStatus.xhtml',
                jar: cookieJar,
                method: "POST",
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                data: `form=form&form:captchaUrl=initial&form:run=${req.body.run}&form:selectDocType=CEDULA&form:docNumber=${req.body.ndocumento}&form:inputCaptcha=${req.body.captcha.respuesta}&form:buttonHidden=&javax.faces.ViewState=${req.body.captcha.javax}`,
                timeout: 4000,
                withCredentials: true,
            })).data
        } catch (error) {
            return res.status(500).send({ error: "No se pudo conectar con el registro civil" })
        }


        if (result.indexOf("Captcha inválido, por favor intente nuevamente") != -1) return res.status(403).send({ error: "Captcha inválido por favor intentelo nuevamente, puede ser que deba intentarlo al menos unas 6 veces", codigo: 5000 })
        if (result.indexOf("La información ingresada no corresponde en nuestros registros") != -1) return res.status(403).send({ error: "La información ingresada no corresponde en nuestros registros, probablemente ingreso mal el Número de serie o documento", codigo: 5001 })
        if (result.indexOf("No Vigente") != -1) return res.status(403).send({ error: "Carnet no vigente", codigo: 5002 })
        if (result.indexOf("Problemas con el servidor.Contacte el administrador.") != -1) return res.status(403).send({ error: "Error registro civil, intente de nuevo más tarde", codigo: 5003 })
        if (result.indexOf("class=\"setWidthOfSecondColumn\">Vigente</td>") == -1) return res.status(403).send({ error: "Error desconocido", codigo: 5003 })

        token = {
            _id: generateToken(30),
            time: Date.now() + 60 * 60 * 1000,
            run: req.body.run
        }
        try {
            await tokenstemporales.put(token)
        } catch (error) {
            return res.status(500).send({ error: "Error al generar el Token de respuesta" })
        }

    }


    let autorizados = []
    if (identidad.alumnos) {
        autorizados = (await usuarios.find({
            selector: {
                _id: { $in: identidad.alumnos }
            }
        })).docs
    } else {
        autorizados = [identidad]
    }

    res.send({
        token: token,
        identidadverificada: identidad,
        autorizados: autorizados
    })
});

app.post('/claves/cambiarclave', jsonParser, async (req, res) => {
    if (!req.body.runusuario) return res.status(400).send({ error: "No se encontro el run del usuario en la solicitud" })
    if (!req.body.correousuario) return res.status(400).send({ error: "No se encontro el correo en la solicitud" })
    if (!req.body.token) return res.status(400).send({ error: "No se encontro el token en la solicitud" })
    if (!req.body.clave) return res.status(400).send({ error: "No se encontro la clave en la solicitud" })
    let tokenstemporales = new PouchDBServer("TokensTemporales")
    try {
        let token = await tokenstemporales.get(req.body.token._id)
        if (token.run != req.body.token.run) return res.status(400).send({ error: "El token no coincide con el R.U.N." })
        if (token.time < Date.now()) return res.status(400).send({ error: "El token esta expirado", code: 6000 })
        token.time = Date.now() + 20 * 60 * 1000
        await tokenstemporales.put(token)
    } catch (error) {
        return res.status(400).send({ error: "El token no sirve o esta expirado" })
    }
    let autorizado = false;
    try {
        let identidadusuario = await usuarios.get(req.body.token.run)
        if (identidadusuario._id == req.body.runusuario) {
            if (identidadusuario.correos.includes(req.body.correousuario)) {
                autorizado = true
            }
        } else {
            if (identidadusuario.alumnos && identidadusuario.alumnos.includes(req.body.runusuario)) {
                let alumno = await usuarios.get(req.body.runusuario)
                if (alumno.correos.includes(req.body.correousuario)) {
                    autorizado = true
                }
            }
        }
    } catch (error) {
        return res.status(400).send({ error: "No se pudo autorizar su solicitud" })
    }

    const service = google.admin({ version: 'directory_v1', auth: auth });
    try {
        await service.users.update({ userKey: req.body.correousuario, requestBody: { password: req.body.clave } })
        res.send({ code: 200 })
    } catch (error) {
        if (error && error.code == 403) return res.send({ error: "La página web no se encuentra autorizada para cambiar está clave, por favor contacta con soporte" })
        res.send({ error: "La página no pudo cambiar la clave, intenta nuevamente o cumunicate con soporte" })
    }
})


app.post('/solicitarcuentas/solicitudeshechaspormi', jsonParser, async (req, res) => {
    if (!req.body.id_token) return res.status(400).send({ error: "No se encontro el id_token en la solicitud" })
    let identidad;
    try {
        identidad = await obtenerIdentidad(req.body.id_token);
    } catch (error) {
        return res.status(401).send(error)
    }
    let solicitudesdb = new PouchDBServer("Solicitudes")
    try {
        return res.send({
            solicitudes: (await solicitudesdb.find({
                selector: {
                    solicitante: identidad.correologeado,
                    fechasolicitud: { $gte: null }
                },
                sort: [{ fechasolicitud: 'desc' }, { solicitante: 'desc' }],
                use_index: "ordenar"
            })).docs
        })

    } catch (error) {
        console.log(error)
        return res.status(500).send({ error: "Hay un error en el servidor", catch: error, identidad: identidad })
    }
})

app.post('/solicitarcuentas/todaslassolicitudes', jsonParser, async (req, res) => {
    if (!req.body.id_token) return res.status(400).send({ error: "No se encontro el id_token en la solicitud" })
    let identidad;
    try {
        identidad = await obtenerIdentidad(req.body.id_token);
    } catch (error) {
        return res.status(401).send(error)
    }
    if (identidad.tipo != "Administrador") return res.status(401).send({ error: "No estas autorizado" })
    let solicitudesdb = new PouchDBServer("Solicitudes")
    try {
        return res.send({
            solicitudes: (await solicitudesdb.find({
                selector: {
                    solicitante: { $gte: null },
                    fechasolicitud: { $gte: null }
                },
                sort: [{ fechasolicitud: 'desc' }, { solicitante: 'desc' }],
                use_index: "ordenar"
            })).docs
        })
    } catch (error) {
        console.log(error)
        return res.status(500).send({ error: "Hay un error en el servidor", catch: error, identidad: identidad })
    }
})

app.post('/solicitarcuentas/enviarsolicitud', jsonParser, async (req, res) => {
    if (!req.body.id_token) return res.status(400).send({ error: "No se encontro el id_token en la solicitud" })
    if (!req.body.solicitudes) return res.status(400).send({ error: "No se encontro las solicitudes en la solicitud" })
    let identidad;
    try {
        identidad = await obtenerIdentidad(req.body.id_token);
    } catch (error) {
        return res.status(401).send(error)
    }
    let respuesta = [];

    req.body.solicitudes.forEach((raw) => {
        let b = {}

        if (raw.run && typeof raw.run == "string") b.run = raw.run
        else return;
        if (raw.nombre && typeof raw.nombre == "string") b.nombre = raw.nombre
        else return;
        if (raw.apellido && typeof raw.apellido == "string") b.apellido = raw.apellido
        else return;
        if (raw.curso && typeof raw.curso == "string") b.curso = raw.curso
        if (raw.tipo && typeof raw.tipo == "string") b.tipo = raw.tipo
        else return;
        if (raw.letra && typeof raw.letra == "string") b.letra = raw.letra
        if (raw.modalidad && typeof raw.modalidad == "string") b.modalidad = raw.modalidad
        if (raw.tipo == "Alumno" && raw.apoderados && Array.isArray(raw.apoderados) && (raw.apoderados = raw.apoderados.filter((e) => typeof e == "string")).length > 0) b.apoderados = raw.apoderados

        if (raw._id && typeof raw._id == "string" && raw._rev && typeof raw._rev == "string") {
            b._id = raw._id;
            b._rev = raw._rev;
        }

        if (raw._deleted && typeof raw._deleted == "boolean" && b._id && b._rev) {
            b._deleted = raw._deleted;
        }

        if (raw.estado && raw.estado.tipo && raw.estado.texto) {
            var tipo = raw.estado.tipo
            var texto = raw.estado.texto
            if (tipo == "info" && texto == "Enviando") b.estado = { tipo: "warning", texto: "Enviado" }
            else if (tipo == "info" && texto == "Por eliminar") b.estado = { tipo: "info", texto: "Por eliminar" }
            else return;
        } else {
            b.estado = { tipo: "danger", texto: "Error" }
        }

        if (Object.entries(b).length != 0) {
            if (!b.solicitante) {
                b.solicitante = identidad.correologeado
            }
            if (!b.fechasolicitud) b.fechasolicitud = Date.now()
            respuesta.push(b)
        }
    });

    let solicitudesdb = new PouchDBServer("Solicitudes")
    try {
        await solicitudesdb.bulkDocs(respuesta)
    } catch (error) {
    }

    try {
        return res.send({
            solicitudes: (await solicitudesdb.find({
                selector: {
                    solicitante: identidad.correologeado,
                    fechasolicitud: { $gte: null }
                },
                use_index: "ordenar",
                sort: [{ fechasolicitud: 'desc' }, { solicitante: 'desc' }]
            })).docs
        })
    } catch (error) {
        return res.status(500).send({ error: "Hay un error en el servidor", catch: error, identidad: identidad })
    }
})

app.post('/solicitarcuentas/admin/editarsolicitud', jsonParser, async (req, res) => {
    if (!req.body.id_token) return res.status(400).send({ error: "No se encontro el id_token en la solicitud" })
    if (!req.body.usuario) return res.status(400).send({ error: "No se encontro el usuario en la solicitud" })

    let identidad;
    try {
        identidad = await obtenerIdentidad(req.body.id_token);
    } catch (error) {
        return res.status(401).send(error)
    }
    if (identidad['tipo'] != "Administrador") return res.status(401).send({ error: "No tienes permiso para hacer esto" })

    let raw = req.body.usuario;
    let b = {}

    if (raw.run && typeof raw.run == "string") b.run = raw.run
    else return res.status(401).send({ error: "No se encontro R.U.N." })
    if (raw.nombre && typeof raw.nombre == "string") b.nombre = raw.nombre
    else return res.status(401).send({ error: "No se encontro el nombre." })
    if (raw.apellido && typeof raw.apellido == "string") b.apellido = raw.apellido
    else return res.status(401).send({ error: "No se encontro el apellido." });
    if (raw.curso && typeof raw.curso == "string") b.curso = raw.curso
    if (raw.tipo && typeof raw.tipo == "string") b.tipo = raw.tipo
    else return res.status(401).send({ error: "No se encontro el tipo." });
    if (raw.letra && typeof raw.letra == "string") b.letra = raw.letra
    if (raw.modalidad && typeof raw.modalidad == "string") b.modalidad = raw.modalidad
    if (raw.tipo == "Alumno" && raw.apoderados && Array.isArray(raw.apoderados) && (raw.apoderados = raw.apoderados.filter((e) => typeof e == "string")).length > 0) b.apoderados = raw.apoderados

    if (raw._id && typeof raw._id == "string" && raw._rev && typeof raw._rev == "string") {
        b._id = raw._id;
        b._rev = raw._rev;
    } else {
        return res.status(401).send({ error: "No se encontro el id o el rev." });
    }

    if (raw._deleted && typeof raw._deleted == "boolean" && b._id && b._rev) {
        b._deleted = raw._deleted;
    }

    if (raw.estado && raw.estado.tipo && raw.estado.texto) {
        var tipo = raw.estado.tipo
        var texto = raw.estado.texto
        if (tipo == "info" && texto == "Enviando") b.estado = { tipo: "warning", texto: "Enviado" }
        else b.estado = raw.estado
    }

    if (raw.solicitante && typeof raw.solicitante == "string") b.solicitante = raw.solicitante
    else return res.status(401).send({ error: "No se encontro el solicitante." });

    if (Object.entries(b).length != 0) {
        if (!b.fechasolicitud) b.fechasolicitud = Date.now()
        let solicitudesdb = new PouchDBServer("Solicitudes")
        try {
            await solicitudesdb.put(b)
            return res.send(await solicitudesdb.get(b._id))
        } catch (error) {
            res.status(401).send({ error: "Error en la solicitud." });
        }
    } else return res.status(401).send({ error: "Error en la solicitud." });

})

app.post('/solicitarcuentas/admin/aceptarsolicitud', jsonParser, async (req, res) => {
    if (!req.body.id_token) return res.status(400).send({ error: "No se encontro el id_token en la solicitud" })
    if (!req.body.usuario) return res.status(400).send({ error: "No se encontro el usuario en la solicitud" })

    let identidad;
    try {
        identidad = await obtenerIdentidad(req.body.id_token);
    } catch (error) {
        return res.status(401).send(error)
    }
    if (identidad['tipo'] != "Administrador") return res.status(401).send({ error: "No tienes permiso para hacer esto" })

    let solicitudesdb = new PouchDBServer("Solicitudes")
    let usuario = await solicitudesdb.get(req.body.usuario._id)
    let nombres = usuario.nombre
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase().split(" ")
    let apellidos = usuario.apellido
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase().split(" ")
    let correo = `${nombres[0]}.${apellidos[0]}@cicpolmue.cl`
    try {
        if ((await usuarios.find({
            selector: {
                correos: {
                    $elemMatch: correo
                }
            }
        })).docs.length > 0) {
            if (apellidos.length > 1 && apellidos[1].length >= 1) {
                correo = `${nombres[0]}.${apellidos[0]}.${apellidos[1][0]}@cicpolmue.cl`
                if ((await usuarios.find({
                    selector: {
                        correos: {
                            $elemMatch: correo
                        }
                    }
                })).docs.length > 0) {
                    if (apellidos[1].length > 1) {
                        correo = `${nombres[0]}.${apellidos[0]}.${apellidos[1]}@cicpolmue.cl`
                        if ((await usuarios.find({
                            selector: {
                                correos: {
                                    $elemMatch: correo
                                }
                            }
                        })).docs.length > 0) {
                            return res.status(400).send({ error: "No se pudo generar el correo automaticamente, porfavor creelo manualmente" })
                        }
                    }
                    else {
                        return res.status(400).send({ error: "No se pudo generar el correo automaticamente, porfavor creelo manualmente" })
                    }
                }
            }
            else {
                return res.status(400).send({ error: "No se pudo generar el correo automaticamente, porfavor creelo manualmente" })
            }
        }
    } catch (error) {
        return res.status(500).send({ error: "Error en el sistema" })
    }

    const service = google.admin({ version: 'directory_v1', auth: auth });
    let unidadadministrativa
    try {
        unidadadministrativa = (await configdb.get("UnidadesAdministrativas"))[usuario.tipo]
    } catch (error) {
        return res.status(500).send({ error: `El tipo de usuario ${usuario.tipo} no esta registrado en la base de datos` })
    }
    try {
        // console.log({
        await service.users.insert({
            requestBody: {
                orgUnitPath: unidadadministrativa,
                primaryEmail: correo,
                name: {
                    givenName: usuario.nombre,
                    familyName: usuario.apellido
                },
                changePasswordAtNextLogin: false,
                password: generateToken(16)
            }
        })
    } catch (error) {
        if (error && error.code == 403) return res.send({ error: "La página web no se encuentra autorizada para cambiar está clave, por favor contacta con soporte" })
        res.send({ error: "La página no pudo cambiar la clave, intenta nuevamente o cumunicate con soporte" })
    }
    try {
        usuario.estado = { tipo: "success", texto: "Creada" }
        usuario.correo = correo
        await solicitudesdb.put(usuario)
        res.send(await solicitudesdb.get(usuario._id))
    } catch (error) {
        return res.send({ error: "La página creo el usuario pero no se actualizo en la base de datos contacte a soporte" })
    }
})

app.post('/listadeusuarios', jsonParser, async (req, res) => {
    if (!req.body.id_token) return res.status(400).send({ error: "No se encontro el id_token en la solicitud" })

    let identidad;
    try {
        identidad = await obtenerIdentidad(req.body.id_token);
    } catch (error) {
        return res.status(401).send(error)
    }

    let opciones = {
        selector: {
            correos: {
                $gte: null
            }
        },
        limit: 30
    };
    if (req.body.skip) {
        opciones['skip'] = req.body.skip
    }
    if (identidad['tipo'] == "Administrador" || identidad['tipo'] == "Trabajador") {
        if (req.body.tipo) {
            opciones['selector']['tipo'] = req.body.tipo
        }

        if (req.body.modalidad) {
            opciones['selector']['modalidad'] = req.body.modalidad
        }

        if (req.body.letra) {
            opciones['selector']['letra'] = req.body.letra
        }

        if (req.body.curso) {
            opciones['selector']['curso'] = req.body.curso
        }

    } else {
        if (!identidad.modalidad) return res.status(500).send({ error: "El alumno no tiene registrada la modalidad" })
        if (!identidad.curso) return res.status(500).send({ error: "El alumno no tiene registrada el curso" })
        if (!identidad.letra) return res.status(500).send({ error: "El alumno no tiene registrada la letra" })
        opciones['selector']['tipo'] = "Alumno"
        opciones['selector']['modalidad'] = identidad.modalidad
        opciones['selector']['letra'] = identidad.letra
        opciones['selector']['curso'] = identidad.curso
        opciones['fields'] = ['curso', 'letra', 'nombre', 'correos', 'apellido', 'modalidad', 'tipo', 'creationTime']
    }

    if (!opciones.selector || !opciones.selector.tipo) {
        return res.status(500).send({ error: "Se requiere de un tipo de usuario" })
    }

    if (opciones.selector.tipo == "Trabajador") {
        opciones['fields'] = ['curso', 'letra', 'nombre', 'correos', 'apellido', 'modalidad', 'tipo', 'creationTime']
    }

    return res.send({
        usuarios: (await usuarios.find(opciones)).docs
    })
})
app.use('/', ExpressPouchDB(PouchDBServer));

app.listen(8000, () => {
    console.log(`Servidor iniciado en ${new Date()}`);
});
