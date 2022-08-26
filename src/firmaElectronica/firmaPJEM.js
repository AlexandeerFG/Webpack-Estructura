var firmaPJEM = {};

firmaPJEM.environment = {//Aqui pueden ir los parametros de configuración que son constantes y no configurables, al menos no desde el navegador
    production: 0,
    scapeUrl: "../../",
    controllerUrl: "controller/firmaelectronicav2/FirmaElectronicaControllerv2.php",
    idCer: "cerFejem",
    idKey: "keyFejem",
    idPass: "passwordFejem",
    cveSistema: 30
};
//Bloqueamos los campos
if (typeof Object.freeze === "function") {
    Object.freeze(firmaPJEM.environment);
}


firmaPJEM.Firma = function () {
    /*
     Posibles respuestas status => 
     success: Firmado o correcto 
     warning: alertas
     error : alertas de errores o fallos
     sign : se puede firmar
     info: alerta simple
     empty: sin resultados 
     */
    return {
        //parametros
        idReferencia: [],
        idReferenciaMissing: [], //Se pueden Firmar
        idReferenciaSigned: [], //Ya estan Firmados
        idReferenciaError: [], //Tiene un error
        digestiones: [], //Aqui guarda las digestiones para enviarlas a fielnet (js)
        cveTipoDocumentoFirma: 0, //el tipo de documento de firma electronica, referente a gestion
        cveTipoDocumentoOrigen: [], //se guardan los tipos de documentos a consultar dentro del sistema local puede ser un String o un array()  => //lo ideal es que se cargue desde la tabla de gestion cuando solo sea 1
        cveTipoReferencia: [], // Tipo de Actuacion ¿? => puede ser un String o un array()  => //lo ideal es que se cargue desde la tabla de gestion cuando solo sea 1
        descTipoDocumentoOrigen: [], // Tipo de Actuacion ¿? => puede ser un String o un array()  => //lo ideal es que se cargue desde la tabla de gestion cuando solo sea 1
        cveTipoExpediente: 0, //Preguntar a Julio o Augus para que sirve (uso exclusivo electronico¿?) => //lo ideal es que se cargue desde la tabla de gestion
        cveGrupo: 0,
        nombreUsuario: "",
        cveAdscripcion: "",
        extraParams: {},
        //parametros de configuracion
        debugg: 1,
        generarPdf: 0, //Para promociones en línea o que se requiera generar un pdf al firmar ¿?  
        anticipada: 0, //para generar la hoja de evidencias, sin importar cuantas firmas tenga
        validCurp: 0,
        modeloGestion: 0, //Indicar si el juzgado puede firmar electronicamente o no 0 = no pude || 1 = puede firmar 
        showModal: 1,
        functionModal: "", //aqui va la funcion que llama a tu modal o lo que deba hacer para firmar el documento
        typeOfAlert: 1, //Para indicar el manejo de alertas usando una libreria adicional o el alert por default
        useWebSocket: 0, //Para indicar le uso de un websocket ?????? funcion adicional pendiente
        //Funciones callback
        callbackEnd: null, //Cuando genera el pkcs 7 y la hoja de evidencias
        callback: null, //cuando firma un usuario sin importar el total
        //Parametros que se deberian borrar???
        ignorarFirmaLogin: 0,

        //Funciones Generales
        validateStatusSign: function () {
            try {
                let self = this;
                if (self.useWebSocket) {

                } else {
                    let DataSend = {
                        accion: "validateStatusSign",
                        idReferencia: JSON.stringify(self.idReferencia),
                        cveTipoDocumentoFirma: self.cveTipoDocumentoFirma,
                        cveTipoDocumentoOrigen: JSON.stringify(self.cveTipoDocumentoOrigen),
                        cveTipoReferencia: JSON.stringify(self.cveTipoReferencia),
                        cveTipoExpediente: self.cveTipoExpediente,
                        cveAdscripcion: self.cveAdscripcion,
                        cveGrupo: self.cveGrupo,
                        anticipada: self.anticipada,
                        modeloGestion: self.modeloGestion,
                        generarPdf: self.generarPdf,
                        cveSistema: firmaPJEM.environment.cveSistema, //Es realmente necesario?
                        debugg: self.debugg
                    };
                    $.ajax({
                        type: 'POST',
                        url: firmaPJEM.environment.scapeUrl + firmaPJEM.environment.controllerUrl,
                        data: DataSend,
                        async: false,
                        dataType: 'json',
                        beforeSend: function () {
                            self.idReferenciaMissing = [];
                            self.idReferenciaError = [];
                            self.idReferenciaSigned = [];
                        },
                        success: function (result) {
                            if (result.status === "sign") {
                                self.idReferenciaMissing = result.data.missing;
                                //una vez asignados los ids a firmar, pasamos a firmar. 
                                if (self.idReferenciaMissing.length != 0) { //si los faltantes son mayores de 0
                                    //si esta activada la opcion de mostrar el modal
                                    if (self.showModal) {
                                        if (typeof (self.functionModal) == "function") {
                                            //Mostramos el modal para firma
                                            self.functionModal();
                                        }
                                    }
                                }
                            } else {
                                self.alertGeneral(result.status, result.message);
                            }

                        },
                        error: function (jqXHR, exception) {
                            self.alertGeneral("error", self.detalleErrorAjax(jqXHR, exception));
                        },
                        complete: function () {
                        }
                    });
                }
            } catch (e) {

                console.error(e);
            }
        },

        signFiles: function () {
            let self = this;

            self.divSpinner(true);
            //Leer el certificado
            fielnetPJv2.readCertificate(firmaPJEM.environment.idCer);
            fielnetPJv2.readPrivateKey(firmaPJEM.environment.idKey);
            fielnetPJv2.validateKeyPairs(document.getElementById(firmaPJEM.environment.idPass).value, function (response) {
                if (response.state == 0) {
                    let FechasCert = fielnetPJv2.getFechasCertificado();
                    let FechaHoy = new Date();
                    let fechaToday = FechaHoy.getTime();
                    if (fechaToday >= FechasCert.fechaFinal) {//Hacemos la validacion con el timestamp 
                        console.warn("Certificado Vencido: " + fechaToday + " => " + FechasCert.fechaFinal);
                        self.alertGeneral("warning", "El Certificado se encuentra vencido.");
                        return false;
                    } else {
                        //el certificado se encuentra dentro del rango de fechas valido. 
                        //crear las digestiones 
                        $("#hddDigestionesV2").val("");
                        self.digestiones = [];
                        $.each(self.idReferenciaMissing, function (index, val) {
                            $.each(val.data, function (index, van) {
                                let dig = {
                                    documento: van.singleName,
                                    digestion: van.digestion,
                                    idDocumentosFirmados: van.idDocumentosFirmados,
                                    idReferencia: van.idReferencia,
                                };
                                self.digestiones.push(dig);
                            });
                        });
                        let aux = {
                            digestiones: self.digestiones
                        };

                        $("#hddDigestionesV2").val(JSON.stringify(aux));
                    }
                    self.extraParams = {
                        cveAdscripcion: self.cveAdscripcion,
                        cveTipoDocumentoFirma: self.cveTipoDocumentoFirma,
                        descTipoDocumentoFirma: self.descTipoDocumentoFirma,
                        cveTipoReferencia: self.cveTipoReferencia,
                        cveTipoExpediente: self.cveTipoExpediente,
                        cveGrupo: self.cveGrupo,
                        validCurp: self.validCurp
                    };

                    //fielnetPJ.addExtraParameters(extraParams);

                    fielnetPJv2.signFileDigestv2("hddDigestionesV2", fielnetv2.Digest.SHA2, function (response) {
                        //debugger;
                        self.idReferenciaMissing = [];
                        self.idReferenciaError = [];
                        self.idReferenciaSigned = [];
                        if (response.status == "success") {
                            if (response.data.success.length != 0) {
                                let aux = response.data.success;
                                $.each(aux, function (index, val) {
                                    if (val.generado) {
                                        self.idReferenciaSigned.push(val);
                                    } else {
                                        self.idReferenciaMissing.push(val);
                                    }
                                });
                            }
                            if (response.data.error.length != 0) {
                                let aux = response.data.error;
                                $.each(aux, function (index, val) {
                                    self.idReferenciaError.push(val.idReferencia);
                                });
                            }
                            self.alertGeneral("success", response.message);
                            if (self.idReferenciaSigned.length != 0) {

                                if (typeof self.callbackEnd == "function") {
                                    self.callbackEnd();
                                }
                            } else {
                                if (typeof self.callback == "function") {
                                    self.callback();
                                }
                            }
                        } else {
                            self.alertGeneral("warning", response.message);
                        }
                        console.log(response);
                    });

                    //self.alertGeneral("Info","Hacer Firmado" + FechasCert);
                } else {
                    self.alertGeneral("warning", response.description);
                }

            });
            self.divSpinner(false);
        },

        //Funciones Auxiliares
        detalleErrorAjax: function (jqXHR, exception) {
            var msg = '';
            if (jqXHR.status === 0) {
                msg = 'Sin correci&oacute;n, Verifique su Red.';
            } else if (jqXHR.status == 404) {
                msg = 'No se encontro la p&aacute;gina de la petici&oacute;n, ERROR [404]';
            } else if (jqXHR.status == 500) {
                msg = 'Error interno del servidor, ERROR [500].';
            } else if (exception === 'parsererror') {
                msg = 'La respuesta obtenida no es JSON v&aacute;lido.';
            } else if (exception === 'timeout') {
                msg = 'Se agoto el tiempo de respuesta';
            } else if (exception === 'abort') {
                msg = 'Ajax aborto la petici&oacute;n.';
            } else {
                msg = 'Error desconocido:' + jqXHR.responseText;
            }
            return msg;
        },
        alertGeneral: function (type = "", message = "") {
            let tittle = null;
            let icon = null;
            let alerta = null;
            let self = this;

            if (self.typeOfAlert && typeof ($.alert) == "function") {
                //Aqui va el codigo de la notificacion "personalizada" de cada sistema
                switch (type) {
                    case "success":
                        tittle = "Correcto!";
                        icon = "fas fa-check-circle green-alert alert";
                        break;
                    case "info":
                        tittle = "Informaci&oacute;n!";
                        icon = "fas fa-info-circle blue-alert alert";
                        break;
                    case "warning":
                        tittle = "Alerta!";
                        icon = "fas fa-exclamation-triangle yellow-alert alert";
                        break;
                    case "error":
                        tittle = "Error!";
                        icon = "fas fa-times-circle red-alert alert";
                        break;
                    case "default":
                    default:

                        break;
                }
                let auxtittle = null;
                if (tittle != null) {
                    auxtittle = "<i class='" + icon + "'></i> <label>" + tittle + "</label>";
                }

                alerta = $.alert({
                    title: auxtittle,
                    content: message,
                    confirmButton: "Entendido"
                });

            } else {
                alerta = alert(message);
            }

            return alerta;

        },
        confirmGeneral: function (message, accionAccept = null, paramsAccept = null, accionCancel = null, paramsCancel = null) {
            let alerta = null;
            if (self.typeOfAlert && typeof ($.alert) == "function") {
                alerta = $.confirm({
                    content: mensaje,
                    confirmButton: "Aceptar",
                    cancelButton: "Cancelar",
                    confirm: function () {
                        if (typeof (accionAceptar) == "function") {
                            if (paramsAceptar != null) {
                                accionAceptar(paramsAceptar);
                            } else {
                                accionAceptar();
                            }
                        }
                    },
                    cancel: function () {
                        if (typeof (accionCancelar) == "function") {
                            if (paramsCancelar != null) {
                                accionCancelar(paramsCancelar);
                            } else {
                                accionCancelar();
                            }
                        }
                    }
                });
            } else {
                let aux = confirm(message);
                if (aux) {
                    if (typeof (accionAccept) == "function") {
                        if (paramsAccept != null) {
                            accionAccept(paramsAccept);
                        } else {
                            accionAccept();
                        }
                    }
                } else {
                    if (typeof (accionCancel) == "function") {
                        if (paramsCancel != null) {
                            accionCancel(paramsCancel);
                        } else {
                            accionCancel();
                        }
                    }
                }
                alerta = true;
            }

            return alerta;

        },
        divSpinner: function (show = true) {
            var self = this;
            if (show) {
                self.setCursorByID("spinner", "wait");

                var divsToHide = document.getElementsByClassName("spinner"); //divsToHide is an array
                for (var i = 0; i < divsToHide.length; i++) {
                    //divsToHide[i].style.visibility = "hidden"; // or
                    divsToHide[i].style.display = "block"; // depending on what you're doing
                }


            } else {
                //console.error("Call Spinner Close");
                self.setCursorByID("spinner", "auto");
                var divsToHide = document.getElementsByClassName("spinner"); //divsToHide is an array
                for (var i = 0; i < divsToHide.length; i++) {
                    //divsToHide[i].style.visibility = "hidden"; // or
                    divsToHide[i].style.display = "none"; // depending on what you're doing
                }
            }
        },
        setCursorByID: function (clas = "spinner", cursorStyle = "auto") {
            var elem;
            if (document.getElementById &&
                (elem = document.getElementsByClassName(clas))) {
                if (elem[0].style) elem[0].style.cursor = cursorStyle;
            }
        }

    };

};

