var fielnetv2 = fielnetv2 || {};
var CONTROLLERv2 = "Controlador.ashx";
var ajaxAsync = true;
var evidencev2 = 0;

fielnetv2.Format = {
    HEX: 0,
    B64: 1
};

fielnetv2.Digest = {
    MD5: 1,
    SHA1: 2,
    SHA2: 3
};

fielnetv2.Encoding = {
    UTF8: 2,
    B64: 3
};

fielnetv2.Storages = {
    LOCAL_STORAGE: 0,
    SESSION_STORAGE: 1
};

fielnetv2.Evidences = {
    NONE: 0,
    TSA: 1,
    NOM: 2,
    TSA_NOM: 3

};

function addScripts(strSubDirectory) {
    if (typeof strSubDirectory == "undefined") {
        strSubDirectory = "";
    }
    var scripts = [
        "util.js",
        "debug.js",
        "jsbn.js",
        "oids.js",
        "asn1.js",
        "sha1.js",
        "sha256.js",
        "md5.js",
        "md.js",
        "prng.js",
        "random.js",
        "jsbn.js",
        "pkcs1.js",
        "rsa.js",
        "cipherModes.js",
        "cipher.js",
        "aes.js",
        "des.js",
        "rc2.js",
        "pbe.js",
        "pem.js",
        "hmac.js",
        "pbkdf2.js",
        "pkcs7.js",
        "pkcs7asn1.js",
        "pkcs12.js",
        "pss.js",
        "mgf1.js",
        "mgf.js",
        "x509.js",
        "pbkdf2.js", //+
        "pki.js"
    ];

    var satLibs = [
        "yahoo/yahoo-min.js",
        "jsrsasign/x509-1.1.js",
        "jsrsasign/asn1-1.0.js",
        "jsbn/jsbn.js", //
        "jsbn/jsbn2.js",
        "jsbn/jsbn2.js",
        "asn1/asn1hex-1.1.js",
        "asn1/asn1.js",
        "asn1/base64.js",
        "jsrsasign/base64.js",
        "cryptojs/pbkdf2.js",
        "cryptojs/enc-base64.js",
        "rsa/rsa.js",
        "rsa/rsa2.js",
        "rsa/rsasign-1.2.js",
        "jsrsasign/crypto-1.1.js",
        "sjcl/sjcl.js",
        "cryptojs/tripledes.js"//,
        //"sjcl/sha1.js"
    ];
    var aux = "";
    for (var str in satLibs) {
        aux += "<script src='" + (strSubDirectory.length == 0 ? "" : strSubDirectory + "/") + "" + satLibs[str] + "'></script>";
        document.write("<script src='" + (strSubDirectory.length == 0 ? "" : strSubDirectory + "/") + "" + satLibs[str] + "'></script>");
    }
    for (var str in scripts) {
        aux += "<script src='" + (strSubDirectory.length == 0 ? "" : strSubDirectory + "/") + "forge/" + scripts[str] + "'></script>";
        document.write("<script src='" + (strSubDirectory.length == 0 ? "" : strSubDirectory + "/") + "forge/" + scripts[str] + "'></script>");
    }
    //$("#libsSign").html(aux);
}

if (typeof Object.freeze == "function") {
    Object.freeze(fielnetv2.Digest);
    Object.freeze(fielnetv2.Encoding);
    Object.freeze(fielnetv2.Storages);
}

fielnetv2.Firma = function Firma(oProperties) {
    console.log(oProperties);
    if (typeof oProperties == "object") {
        if (oProperties.controller) {
            CONTROLLERv2 = oProperties.controller;
        }
        if (oProperties.subDirectory) {
            addScripts(String(oProperties.subDirectory));
        } else {
            addScripts();
        }
        if (oProperties.ajaxAsync != undefined) {
            ajaxAsync = oProperties.ajaxAsync;
        }

        if (oProperties.evidence) {
            evidence = oProperties.evidence;
        }
    } else {
        addScripts();
    }

};

fielnetv2.Firma.prototype = (function () {
    //Variables privadas
    var strPrivateKey = null;
    var strCertificate = null;
    var strCerPem;

    var strPfx;
    var fileSizePfx;

    var fileSizeCertificate;
    var fileSizePrivateKey;

    var codigo;
    var transferencia;

    var oPrivateKey;
    //Constantes
    var NOT_FOUND = "El elemento cuyo id ':id' no ha sido encontrado, verifique que ya existe en el DOM";

    var archivosFirmados;

    var strReferencia;
    var extraParameters;

    //Funciones privadas
    function rstrtohex(s) {
        var result = "";
        for (var i = 0; i < s.length; i++) {
            result += ("0" + s.charCodeAt(i).toString(16)).slice(-2);
        }
        return result;
    }

    var XMLHttpFactories = [
        function () {
            return new XMLHttpRequest();
        },
        function () {
            return new ActiveXObject("Msxml2.XMLHTTP");
        },
        function () {
            return new ActiveXObject("Msxml3.XMLHTTP");
        },
        function () {
            return new ActiveXObject("Microsoft.XMLHTTP");
        }
    ];

    function getXMLHttpRequest() {
        var xmlhttp = false;
        for (var i = 0; i < XMLHttpFactories.length; i++) {
            try {
                xmlhttp = XMLHttpFactories[i]();
            } catch (e) {
                continue;
            }
            currentXMLHttpRequest = xmlhttp;
            break;
        }
        return xmlhttp;
    }

    function ajaxRequest(opts) {
        var ajaxRequest = getXMLHttpRequest();
        if (ajaxRequest != null) {
            if (typeof opts.url == "undefined" || opts.url.length == 0) {
                alert("No se ha especificado la url para iniciar la petición");
                return;
            }
            if (typeof opts.method == "undefined") {
                opts.method = "POST";
            }
            //Define el tipo de petición.
            opts.async = ajaxAsync;

            try {
                if (opts.method.toUpperCase() == "GET") {
                    opts.url += "?" + opts.data;
                }
                ajaxRequest.open(opts.method, opts.url, opts.async);
                if (typeof opts.contentType == "undefined") {
                    ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                } else {
                    ajaxRequest.setRequestHeader("Content-Type", opts.contentType);
                }
                if (typeof opts.data != "undefined") {
                    if (typeof opts.data == "string") {
                        //ajaxRequest.setRequestHeader("Content-Length", opts.data.length);
                    }
                }
                if (typeof opts.headers != "undefined") {
                    if (!Array.isArray) {
                        Array.isArray = function (arg) {
                            return Object.prototype.toString.call(arg) === '[object Array]';
                        };
                    }
                    if (Array.isArray(opts.headers)) {
                        for (var key in opts.headers)
                            ajaxRequest.setRequestHeader(key, opts.headers[key]);
                    }
                }
                //Esto aplica para web browsers viejos
                if (typeof ajaxRequest.onloadend == "undefined") {
                    ajaxRequest.onreadystatechange = function (e) {
                        if (ajaxRequest.readyState == 4) { //Cuando la petición esté terminada
                            if (ajaxRequest.status == 200) { //200 exito
                                if (typeof opts.success == "function") {
                                    var data = ajaxRequest.responseText;
                                    opts.success(data, ajaxRequest.status, ajaxRequest);
                                }
                                if (typeof opts.complete == "function") {
                                    var data = ajaxRequest.responseText;
                                    opts.complete(data, ajaxRequest.status, ajaxRequest);
                                }
                            } else { //error
                                if (typeof opts.error == "function") {
                                    var data = ajaxRequest.responseText;
                                    opts.error(data, ajaxRequest.status, ajaxRequest);
                                }
                            }
                        }
                    };
                } //Aplica para web browsers actuales
                else {
                    ajaxRequest.onerror = function (event) {
                        var data = event.currentTarget.responseText;
                        var status = event.currentTarget.status;
                        if (typeof opts.error != "undefined") {
                            if (status == 0) {
                                data = "Error: Verifique que no tenga un firewall que bloquee la petición o que tenga permiso CORS ";
                            }
                            opts.error(data, status, event.currentTarget);
                        } else {
                            alert(data);
                        }
                    };

                    if (typeof opts.success == "function") {
                        ajaxRequest.onload = function (event) {
                            var data = event.currentTarget.responseText;
                            var status = event.currentTarget.status;
                            if (typeof opts.success != "undefined") {
                                opts.success(data, status, event.currentTarget);
                            }
                        };
                    }
                    if (typeof opts.complete == "function") {
                        ajaxRequest.onloadend = function (event) {
                            var data = event.currentTarget.responseText;
                            var status = event.currentTarget.status;
                            if (status == 0) {
                                data = "Error: Verifique que no tenga un firewall que bloquee la petición o que tenga permiso CORS ";
                            }
                            if (typeof opts.complete != "undefined") {
                                opts.complete(data, status, event.currentTarget);
                            }
                        };
                    }
                    if (typeof opts.progress != "undefined") {
                        ajaxRequest.upload.addEventListener("progress", opts.progress, false);
                    }
                }
                if (ajaxAsync) {
                    ajaxRequest.timeout = 300000;
                }
                ajaxRequest.send((opts.method.toUpperCase() == "POST" ? opts.data : null));
            } catch (e) {
                alert("Error: " + e.message);
            }
        }
    }

    function base64ToHex(str) {
        for (var i = 0, bin = atob(str.replace(/[ \r\n]+$/, "")), hex = []; i < bin.length; ++i) {
            var tmp = bin.charCodeAt(i).toString(16);
            if (tmp.length === 1)
                tmp = "0" + tmp;
            hex[hex.length] = tmp;
        }
        return hex.join("");
    }

    function hexToBase64(hex) {
        var base64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        if (typeof hex == "undefined")
            return;
        var bytes = [];
        for (var i = 0, c = 0; c < hex.length; c += 2) {
            bytes.push(parseInt(hex.substr(c, 2), 16));
        }

        for (var base64 = [], i = 0; i < bytes.length; i += 3) {
            var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            for (var j = 0; j < 4; j++) {
                if (i * 8 + j * 6 <= bytes.length * 8)
                    base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
                else
                    base64.push("=");
            }
        }
        return base64.join("");
    }

    function privateKeyObject(strPrivateKey) {
        var pkeyDerEncoded = forge.util.decode64(strPrivateKey);
        var pkeyAsn1Encoded = forge.asn1.fromDer(pkeyDerEncoded);
        var privateKey = forge.pki.privateKeyFromAsn1(pkeyAsn1Encoded);
        return privateKey;
    }

    // End Funciones privadas


    //Interfaz pública

    function validateWebBrowser(strMessage) {
        if (!(window.File && window.FileReader && window.FileList && window.Blob && window.sessionStorage && window.localStorage)) {
            if (typeof strMessage != "undefined") {
                alert(strMessage);
            }
            return false;
        }
        return true;
    }

    function getCertificate() {
        return strCertificate;
    }

    function readCertificate(strIdElement) {
        if (typeof strIdElement == "string") {
            var oItem = document.getElementById(strIdElement);
            if (oItem != null) {
                oItem.setAttribute("accept", ".cer");
                oItem.value = "";
                oItem.onchange = function (evt) {
                    if (oItem.files.length > 0) {
                        var file = new FileReader();
                        file.onload = function () {
                            var bytes = new Uint8Array(file.result);
                            var binary = "";
                            for (var i = 0; i < bytes.byteLength; i++) {
                                binary += String.fromCharCode(bytes[i])
                            }
                            var certHex = rstrtohex(binary);
                            strCertificate = (forge.util.encode64(forge.util.hexToBytes(certHex)));
                            if (fileSizeCertificate != bytes.length) {
                                alert("No se ha podido leer el Certificado por completo");
                                strCertificate = null;
                                return;
                            }
                            strCerPem = KJUR.asn1.ASN1Util.getPEMStringFromHex(certHex, 'CERTIFICATE');
                        };
                        file.onerror = function (e) {
                            alert("Ha ocurrido un error al leer el certificado: " + e);
                        };
                        fileSizeCertificate = oItem.files[0].size;
                        file.readAsArrayBuffer(oItem.files[0]);
                    }
                };
            } else {
                alert(NOT_FOUND.replace(":id", strIdElement));
            }
        } else {
            alert("El argumento no tiene un formato válido se require un valor tipo cadena");
        }
    }

    function decodeCertificate(strCert, bOcsp, fCallback) {
        if (typeof bOcsp == "undefined") {
            bOcsp = true;
        }

        if (typeof strCert == "boolean" && typeof bOcsp == "function") {
            fCallback = bOcsp;
            bOcsp = strCert;
            strCert = strCertificate;
            if (strCert == null) {
                if (typeof fCallback == "function") {
                    var oResult = {};
                    oResult.state = -99;
                    oResult.description = "No se ha cargado ningún certificado";
                    fCallback(oResult);
                }
                return;
            }

        }

        var url = "metodo=decodecert&cert=" + strCert + "&ocsp=" + bOcsp + "&referencia=" + strReferencia;
        ajaxRequest({
            url: CONTROLLERv2,
            method: "POST",
            data: url,
            success: function (oResponse, status, xmlhttp) {
                if (typeof fCallback == "function") {
                    try {
                        var oJSONResponse = JSON.parse(oResponse);
                        fCallback(oJSONResponse);
                    } catch (e) {
                        var oError = {};
                        oError.state = -99;
                        oError.description = "Error leyendo respuesta del servidor: " + e;
                        fCallback(oError);
                    }
                }
            },
            complete: function (data) {
                if (typeof fCallback == "function") {
                }
            },
            error: function (data) {
                if (typeof fCallback == "function") {
                }
            }
        });
    }
    ;

    function readPrivateKey(strIdElement) {
        if (typeof strIdElement == "string") {
            var oItem = document.getElementById(strIdElement);
            if (oItem != null) {
                oItem.setAttribute("accept", ".key");
                oItem.value = "";
                oItem.onchange = function (evt) {
                    if (oItem.files.length > 0) {
                        var fileReader = new FileReader();
                        fileReader.onload = function () {
                            try {
                                var base64Key = fileReader.result.split("base64,")[1];
                                var decode = forge.util.decode64(base64Key);
                                if (fileSizePrivateKey != decode.length) {
                                    alert("No se ha leído la llave privada");
                                    strPrivateKey = null;
                                    return;
                                }
                                strPrivateKey = base64Key;
                            } catch (e) {
                                alert(e);
                            }
                        };
                        fileReader.onerror = function (e) {
                            alert("Ocurrió un error al leer la llave privada: " + e);
                        };
                        fileReader.readAsDataURL(oItem.files[0]);
                        fileSizePrivateKey = oItem.files[0].size;
                    }
                };
            } else {
                alert(NOT_FOUND.replace(":id", strIdElement));
            }
        } else {
            alert("El argumento no tiene un formato válido se require un valor tipo cadena");
        }
    }

    function deriveKeyV1(password, salt, iterations, keySizeInBits, ivSizeInBits) {
        var bytePassword = "";
        var ab = [];
        for (var i = 0; i < password.length; i++) {
            bytePassword += password.charCodeAt(i).toString();
            ab[i] = password.charCodeAt(i).toString();
        }

        var keySize = keySizeInBits / 8;
        var ivSize = ivSizeInBits / 8;
        var md = forge.md.md5.create();
        md.start();
        md.update(password);
        var result = md.update(salt);
        var aux = result.digest().data;
        for (var i = 1; i < iterations; i++) {
            md.start();
            aux = md.update(aux).digest().data;

        }

        var key = null;
        var iv = [];
        key = aux.substr(0, keySize);
        iv = aux.substr(keySize);
        return [key, iv];

    }

    function validateModules(a, b) {
        var iguales = true;
        var i = 0;
        while (typeof a[i] != "undefined" && typeof b[i] != "undefined") {
            if (a[i] != b[i]) {
                iguales = false;
                break;
            }
            i++;
        }
        return iguales;
    }

    function decodeItem(dataCoded) {
        var offset = 0x02;
        var sizeData = "0x" + forge.util.bytesToHex(dataCoded[1]);

        if (sizeData > 0x80) {
            var dByte = sizeData - 0x80;
            offset = 02 + dByte;
            sizeData = 00;
            for (var n = 0; n < dByte; n++) {
                sizeData = (sizeData << 0x08) | dataCoded[02 + n];
            }
        }

        var data = [];
        data = dataCoded.slice(offset);
        return data;
    }

    function firelKey(strKey, certModule, cert, strPass) {
        var format = ASN1HEX.getDecendantHexTLVByNthList(strKey, 0, [0]);
        var algoritmId = ASN1HEX.getDecendantHexTLVByNthList(format, 0, [0]);
        var citer = ASN1HEX.getDecendantHexTLVByNthList(format, 0, [1]);
        var iteraciones = ASN1HEX.getDecendantHexTLVByNthList(citer, 0, [1]);
        var salt = ASN1HEX.getDecendantHexTLVByNthList(citer, 0, [0]);
        citer = decodeItem(decodeItem(salt));
        var saltos = ASN1HEX.getDecendantHexTLVByNthList(iteraciones, 0, [0]);
        var encryptedData = ASN1HEX.getDecendantHexTLVByNthList(strKey, 0, [1]);
        var privateKey = encryptedData.substring(encryptedData.indexOf(ASN1HEX.getDecendantHexTLVByNthList(encryptedData, 0, [0])));

        saltos = parseInt(saltos, 16);
        if (isNaN(saltos)) {
            throw "Error al decodificar la llave privada";
        }
        var deriveKey = deriveKeyV1(strPass, forge.util.hexToBytes(citer), saltos, 64, 64);
        try {
            var cipher = forge.des.createDecryptionCipher(deriveKey[0]);
            cipher.start(deriveKey[1]);
            cipher.update(forge.util.createBuffer(forge.util.hexToBytes(privateKey)));
            cipher.finish();
            var result = cipher.output.toHex();
            if (result.indexOf("30") != 0) {
                throw "Archivos .KEY, .CER y/o contraseña incorrectos (No se ha podido acceder a la llave privada).";
            } else {
                var pkey = privateKeyObject(hex2b64(cipher.output.toHex()));
                var moduloPkey = pkey.n;
                if (!validateModules(certModule, moduloPkey.data)) {
                    throw "No existe relación entre el certificado y la llave privada seleccionada";
                } else {
                    oPrivateKey = hexToBase64(result);
                    strCertificate = cert;
                    return [0, "La verificación del par de llaves ha sido satisfactoria"];
                }
            }
        } catch (e) {
            throw e;
        }
    }

    function validateKeyPairs(strPass, fCallback) {
        //alert('El servicio de la firma electronica esta en mantenimiento');
        //return false;
        var oResult = {};
        if (strCertificate != null) {
            if (strPrivateKey != null) {
                var oResult = {};
                if (typeof strPass != "undefined") {
                    if (strCerPem != null && strPrivateKey != null) {
                        var certificate = new X509();
                        certificate.readCertPEM(strCerPem);
                        var certModule = certificate.subjectPublicKeyRSA.n;
                        try {
                            var privateKeyDecoded = ASN1.decode(Base64.unarmor(strPrivateKey));
                            var privateKeyHex = obtieneLlavePrivada(privateKeyDecoded.toHexString(), strPass);
                            var privateKeyB64 = hexToBase64(privateKeyHex);
                            var rsakey = getKeyFromPlainPrivatePKCS8Hex(privateKeyHex);
                            var moduloPrivada = rsakey.n;
                        } catch (e) {
                            if (e.indexOf("PKCS8 private key(code:001)") != -1) {
                                oResult.state = -97;
                                oResult.description = "La contraseña para acceder a la llave privada no es correcta, intente de nuevo.";
                            } else if (e.indexOf("this only supports pkcs5PBES2") != -1) {
                                try {
                                    var description = firelKey(privateKeyDecoded.toHexString(), certModule, hexToBase64(certificate.hex), strPass);
                                    if (description.length == 2) {
                                        oResult.state = description[0];
                                        oResult.description = description[1];
                                    }
                                } catch (e) {
                                    oResult.state = -95;
                                    oResult.description = e;
                                }
                            } else {
                                oResult.state = -95;
                                oResult.description = "Error: " + e;
                            }
                            if (typeof fCallback != "undefined") {
                                fCallback(oResult);
                            }
                            return;
                        }
                        if (typeof moduloPrivada != "undefined") {
                            if (certModule.equals(moduloPrivada)) {
                                oPrivateKey = privateKeyB64;
                                strCertificate = hexToBase64(certificate.hex);
                                oResult.state = 0;
                                oResult.description = "La verificación del par de llaves ha sido satisfactoria";
                            } else {
                                oResult.estado = -99;
                                oResult.descripcion = "El certificado no corresponde con la llave privada proporcionada";
                            }
                        } else {
                            oResult.state = -98;
                            oResult.description = "No se ha podido entender la llave privada";
                        }

                    }
                }
                if (typeof fCallback != "undefined") {
                    fCallback(oResult);
                }

            } else {
                alert("No se ha cargado la llave privada");
            }

        } else {
            alert("No se ha cargado la llave el certificado");
        }
    }

    function readPfx(strId) {
        if (typeof strId != "undefined") {
            var oItem = document.getElementById(strId);
            if (oItem != null) {
                oItem.setAttribute("accept", ".pfx");
                oItem.value = "";
                oItem.onchange = function (e) {
                    if (oItem.files.length > 0) {
                        var fileReader = new FileReader();
                        fileReader.onload = function (e) {
                            var dataItems = e.target.result.split("base64,");
                            var decode = forge.util.decode64(dataItems[1]);
                            if (decode.length != fileSizePfx) {
                                strPfx = null;
                                alert("Ha ocurrido un error en la lectura del PFX: No se ha podido leer el archivo por completo");
                                return;
                            }
                            if (dataItems.length == 2) {
                                strPfx = dataItems[1];
                            }
                        }
                        fileReader.readAsDataURL(oItem.files[0]);
                        fileSizePfx = e.target.files[0].size;
                        fileReader.onerror = function (e) {
                            strPfx = null;
                            alert("Ha ocurrido un error en la lectura del archivo PFX " + e.target.error.code);
                        };
                    }
                };
            }
        }

    }

    function openPfx(strPass, fCallback) {
        var oResult = {};
        if (typeof strPass != "string") {
            strPass = String(strPass);
        }

        if (typeof strPfx != "undefined") {
            try {
                var pfxDerEncoded = forge.util.decode64(strPfx);
                var pfxAsn1Encoded = forge.asn1.fromDer(pfxDerEncoded);
                var pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1Encoded, strPass);
                strPass = null;
                var keyBags = pfx.getBags({
                    bagType: forge.pki.oids.pkcs8ShroudedKeyBag
                });
                var bag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
                var privateKey = bag.key;
                var keyAsn1Encoded = forge.pki.privateKeyToAsn1(privateKey);
                var keyDerEncoded = forge.asn1.toDer(keyAsn1Encoded);
                oPrivateKey = forge.util.encode64(keyDerEncoded.getBytes());
                var certBags = pfx.getBags({
                    bagType: forge.pki.oids.certBag
                });
                var certificate = certBags[forge.pki.oids.certBag][0].cert;
                var certAsn1Encoded = forge.pki.certificateToAsn1(certificate);
                var certDerEncoded = forge.asn1.toDer(certAsn1Encoded);
                strCertificate = forge.util.encode64(certDerEncoded.getBytes());
                oResult.state = 0;
                oResult.description = "Encapsulado abierto satisfactoriamente";
            } catch (e) {
                oResult.state = -97;
                oResult.description = (e.message.indexOf("password") > 0 ? "Frase de acceso no válido" : e.message);
            }
        } else {
            oResult.state = -98;
            oResult.description = "No se ha especificado el encapsulado PFX";
        }
        if (typeof fCallback == "function") {
            fCallback(oResult);
        }
    }

    function signPKCS1(strText, iAlgoritm, iCodification, fCallback, bInternalRegisterSign, strVector) {
        var oResult = {};
        var mainArgs = arguments;
        if (oPrivateKey != null) {
            try {
                var privateKey = privateKeyObject(oPrivateKey);
                var kindDigest = null;
                switch (iAlgoritm) {
                    case fielnetv2.Digest.MD5:
                        kindDigest = forge.md.md5.create();
                        break;
                    case fielnetv2.Digest.SHA1:
                        kindDigest = forge.md.sha1.create();
                        break;
                    case fielnetv2.Digest.SHA2:
                        kindDigest = forge.md.sha256.create();
                        break;
                    default:
                        kindDigest = forge.md.sha1.create();
                }

                switch (iCodification) {
                    case fielnetv2.Encoding.UTF8:
                    case fielnetv2.Encoding.B64:
                        break;
                    default:
                        iCodification = fielnetv2.Encoding.UTF8;
                }
                if (iCodification == fielnetv2.Encoding.B64) {
                    try {
                        kindDigest.update(forge.util.text.utf8.decode(forge.util.binary.base64.decode(strText)), "utf8");
                    } catch (encodingException) {
                        kindDigest.update(forge.util.decode64(strText), "raw");
                    }
                } else {
                    kindDigest.update(strText, "utf8");
                }
                oResult.state = 0;
                oResult.sign = forge.util.encode64(privateKey.sign(kindDigest));

            } catch (e) {
                oResult.state = -98;
                oResult.description = "Error " + e;
            }
        } else {
            oResult.state = -99;
            oResult.description = "No existe una llave privada para realizar la firma";
        }
        if (typeof fCallback == "function") {
            if (iCodification != fielnetv2.Encoding.B64) {
                strText = forge.util.binary.base64.encode(forge.util.text.utf8.encode(strText));

            }
            if (oResult.state == 0) {
                if (bInternalRegisterSign != true) {
                    ajaxRequest({
                        url: CONTROLLERv2,
                        data: "metodo=firmaSimple&codificacion=" + iCodification + "&original=" + strText + "&firma=" + oResult.sign + "&cert=" + strCertificate + "&evidence=" + evidence + "&referencia=" + strReferencia + extraParameters,
                        method: "POST",
                        error: function (data) {
                        },
                        complete: function (data) {
                        },
                        success: function (data, status, xmlhttp) {
                            try {
                                var oJSONResult = JSON.parse(data);
                                oJSONResult.sign = oResult.sign;
                                if (typeof strVector != "undefined") {
                                    oJSONResult.vectorSigned = mainArgs[4];
                                }
                                fCallback(oJSONResult);
                            } catch (e) {
                                var oError = {};
                                oError.state = -99;
                                oError.description = "Error al leer respuesta del servidor: " + e;
                                fCallback(oError);
                            }
                        }
                    });
                } else {
                    var oTempResult = {};
                    oTempResult.state = 0;
                    oTempResult.description = "Firma realizada correctamente";
                    oTempResult.sign = oResult.sign;
                    if (typeof fCallback == "function") {
                        fCallback(oTempResult);
                    }

                }
            } else {
                fCallback(oResult);
            }
        }
    }
    ;

    function signPKCS1v2(strText, iAlgoritm, iCodification, fCallback, bInternalRegisterSign, strVector) {
        var oResult = {};
        var mainArgs = arguments;
        if (oPrivateKey != null) {
            try {
                var privateKey = privateKeyObject(oPrivateKey);
                var kindDigest = null;
                switch (iAlgoritm) {
                    case fielnetv2.Digest.MD5:
                        kindDigest = forge.md.md5.create();
                        break;
                    case fielnetv2.Digest.SHA1:
                        kindDigest = forge.md.sha1.create();
                        break;
                    case fielnetv2.Digest.SHA2:
                        kindDigest = forge.md.sha256.create();
                        break;
                    default:
                        kindDigest = forge.md.sha1.create();
                }

                switch (iCodification) {
                    case fielnetv2.Encoding.UTF8:
                    case fielnetv2.Encoding.B64:
                        break;
                    default:
                        iCodification = fielnetv2.Encoding.UTF8;
                }
                if (iCodification == fielnetv2.Encoding.B64) {
                    try {
                        kindDigest.update(forge.util.text.utf8.decode(forge.util.binary.base64.decode(strText)), "utf8");
                    } catch (encodingException) {
                        kindDigest.update(forge.util.decode64(strText), "raw");
                    }
                } else {
                    kindDigest.update(strText, "utf8");
                }
                oResult.state = 0;
                oResult.sign = forge.util.encode64(privateKey.sign(kindDigest));

            } catch (e) {
                oResult.state = -98;
                oResult.description = "Error " + e;
            }
        } else {
            oResult.state = -99;
            oResult.description = "No existe una llave privada para realizar la firma";
        }
        if (typeof fCallback == "function") {
            if (iCodification != fielnetv2.Encoding.B64) {
                strText = forge.util.binary.base64.encode(forge.util.text.utf8.encode(strText));

            }
            if (oResult.state == 0) {
                if (bInternalRegisterSign != true) {
                    ajaxRequest({
                        url: CONTROLLERv2,
                        data: "metodo=firmaSimple&codificacion=" + iCodification + "&original=" + strText + "&firma=" + oResult.sign + "&cert=" + strCertificate + "&evidence=" + evidence + "&referencia=" + strReferencia + extraParameters,
                        method: "POST",
                        error: function (data) {
                        },
                        complete: function (data) {
                        },
                        success: function (data, status, xmlhttp) {
                            try {
                                var oJSONResult = JSON.parse(data);
                                oJSONResult.sign = oResult.sign;
                                if (typeof strVector != "undefined") {
                                    oJSONResult.vectorSigned = mainArgs[4];
                                }
                                fCallback(oJSONResult);
                            } catch (e) {
                                var oError = {};
                                oError.state = -99;
                                oError.description = "Error al leer respuesta del servidor: " + e;
                                fCallback(oError);
                            }
                        }
                    });
                } else {
                    var oTempResult = {};
                    oTempResult.state = 0;
                    oTempResult.description = "Firma realizada correctamente";
                    oTempResult.sign = oResult.sign;
                    if (typeof fCallback == "function") {
                        fCallback(oTempResult);
                    }

                }
            } else {
                fCallback(oResult);
            }
        }
    }
    ;

    function signPKCS1OffLine(strText, iAlgoritm, iCodification, fCallback, bInternalRegisterSign, strVector) {
        var oResult = {};
        var mainArgs = arguments;
        if (oPrivateKey != null) {
            try {
                var privateKey = privateKeyObject(oPrivateKey);
                var kindDigest = null;
                switch (iAlgoritm) {
                    case fielnetv2.Digest.MD5:
                        kindDigest = forge.md.md5.create();
                        break;
                    case fielnetv2.Digest.SHA1:
                        kindDigest = forge.md.sha1.create();
                        break;
                    case fielnetv2.Digest.SHA2:
                        kindDigest = forge.md.sha256.create();
                        break;
                    default:
                        kindDigest = forge.md.sha1.create();
                }

                switch (iCodification) {
                    case fielnetv2.Encoding.UTF8:
                    case fielnetv2.Encoding.B64:
                        break;
                    default:
                        iCodification = fielnetv2.Encoding.UTF8;
                }
                if (iCodification == fielnetv2.Encoding.B64) {
                    try {
                        kindDigest.update(forge.util.text.utf8.decode(forge.util.binary.base64.decode(strText)), "utf8");
                    } catch (encodingException) {
                        kindDigest.update(forge.util.decode64(strText), "raw");
                    }
                } else {
                    kindDigest.update(strText, "utf8");
                }
                oResult.state = 0;
                oResult.sign = forge.util.encode64(privateKey.sign(kindDigest));

            } catch (e) {
                oResult.state = -98;
                oResult.description = "Error " + e;
            }
        } else {
            oResult.state = -99;
            oResult.description = "No existe una llave privada para realizar la firma";
        }
        if (typeof fCallback == "function") {
            if (iCodification != fielnetv2.Encoding.B64) {
                strText = forge.util.binary.base64.encode(forge.util.text.utf8.encode(strText));

            }
            if (oResult.state == 0) {
                fCallback(oResult);
            } else {
                fCallback(oResult);
            }
        }
    }
    ;

    function signPKCS1WithKeyPairs(strCertificateParam, strPrivateKeyParam, strPass, strText, iAlgoritm, iCodification, fCallback, bInternalRegisterSign) {
        strCertificate = strCertificateParam;
        strPrivateKey = strPrivateKeyParam;
        validateKeyPairs(strPass, function (oResult) {
            if (oResult.state == 0) {
                signPKCS1(strText, iAlgoritm, iCodification, function (oSignResult) {
                    if (typeof fCallback == "function") {
                        fCallback(oSignResult);
                    }
                }, bInternalRegisterSign);
            } else {
                if (typeof fCallback == "function") {
                    fCallback(oResult);
                }
            }
        });

    }

    function signPkcs1WithPfx(strPfxParam, strPass, strText, iAlgoritm, iCodification, fCallback, bInternalRegisterSign) {
        strPfx = strPfxParam;
        openPfx(strPass, function (oResult) {
            if (oResult.state == 0) {
                signPKCS1(strText, iAlgoritm, iCodification, function (oSignResult) {
                    if (typeof fCallback == "function") {
                        fCallback(oSignResult);
                    }
                }, bInternalRegisterSign);
            } else {
                if (typeof fCallback == "function") {
                    fCallback(oResult);
                }
            }
        });
    }

    function verifySign(strCadenaOriginal, strFirma, strCertificate, fCallback) {
        ajaxRequest({
            url: CONTROLLERv2,
            data: "metodo=pkcs1&codificacion=3&original=" + strCadenaOriginal + "&firma=" + strFirma + "&cert=" + strCertificate + extraParameters,
            method: "POST",
            complete: function (data, status, jqxhr) {
                if (console.log) {
                    console.log(data);
                }
            },
            error: function (data, status, jqxhr) {
                if (console.log) {
                    console.log(data);
                }
            },
            success: function (data, status, jqxhr) {
                var JSONResponse = JSON.parse(data);
                if (typeof fCallback) {
                    fCallback(JSONResponse);
                }
            }
        });
    }

    function setReferencia(referencia) {
        strReferencia = referencia;
    }

    function padding(val) {
        return val.length == 1 ? "0" + val : val;
    }

    function getCertificateObject(strB64Certificate) {
        try {
            var certDerBytes = forge.util.decode64(strB64Certificate);
            var obj = forge.asn1.fromDer(certDerBytes);
            var cert = forge.pki.certificateFromAsn1(obj);
            return cert;
        } catch (e) {
            return null;
        }
    }

    function getSerialNumber(strB64Certificate) {
        if (typeof strB64Certificate == "undefined") {
            strB64Certificate = strCertificate;
        }
        if (strB64Certificate != null) {
            var certDerBytes = forge.util.decode64(strB64Certificate);
            var obj = forge.asn1.fromDer(certDerBytes);
            var cert = forge.pki.certificateFromAsn1(obj);
            return formatSerialNumber(cert.serialNumber);
        } else {
            return null;
        }

    }

    function formatSerialNumber(strSerialNumber) {
        var strFormato = "";
        for (var i = 0; i < strSerialNumber.length; i += 2) {
            strFormato += strSerialNumber.substr(i, 2) + (i + 2 != strSerialNumber.length ? "." : "");
        }
        return strFormato;
    }


    async function getVectorFilev2(objDigest, iAlgoritm, extraParams, jwtToken, fCallback) {
        console.info("Llego a el metodo getVectorFilev2");
        // let strDigest = JSON.stringify(objDigest);

        // DER
        const derData = {
            debugg: extraParams.debugg,
            cveAdscripcion: extraParams.cveAdscripcion,
            arraydigest: objDigest
        };

        const derResponse = await fetch('http://localhost/api/firma-electronica/der', {
            method: 'POST',
            body: JSON.stringify(derData),
            headers: {
                'Content-Type': 'application/json',
                'sessionData': jwtToken
            }
        });

        const oResult = await derResponse.json();

        if (oResult.state == 0) {
            if (oResult.data.success.length != 0) {
                //Debera entrar a signPKCS1 =>
                let aux = oResult.data.success;

                let dataVector = [];

                aux.forEach((van) => {
                    signPKCS1(van.digestion, iAlgoritm, fielnetv2.Encoding.B64, (oDataSigned) => {
                        let sign = oDataSigned.sign;
                        let vec = van.digestion.replace('=', '');
                        vec = vec.replace('\"', '');
                        let auxVec = {
                            vector: van.digestion.replace('=', ''),
                            firma: sign.replace('==', ''),
                            cert: strCertificate,
                            idDocumento: van.idDocumento,
                            referencia: van.idReferencia,
                            extraParameters: {
                                cveAdscripcion: extraParams.cveAdscripcion,
                                cveTipoDocumentoFirma: extraParams.cveTipoDocumentoFirma,
                                cveGrupo: extraParams.cveGrupo,
                                validCurp: 0
                            }
                        };
                        dataVector.push(auxVec);
                    }, true, van.digestion);
                });

                console.info("Crear vector");
                if (dataVector.length == aux.length) {
                    const vectorData = {
                        debugg: extraParams.debugg,
                        cveAdscripcion: extraParams.cveAdscripcion,
                        vector: dataVector
                    };

                    const vectorResponse = await fetch('http://localhost/api/firma-electronica/vector', {
                        method: 'POST',
                        body: JSON.stringify(vectorData),
                        headers: {
                            'Content-Type': 'application/json',
                            'sessionData': jwtToken
                        }
                    });

                    oJSONResponse = await vectorResponse.json();

                    let responseVec = [];

                    if (oJSONResponse.state != 0) {
                        firmav2.alertGeneral("warning", oJSONResponse.message);
                        return false;
                    }

                    let aux = oJSONResponse.data.success;

                    aux.forEach((val) => {
                        dataVector.forEach((van) => {
                            if ((val.idDocumento == van.idDocumento) && (val.idReferencia == van.referencia)) {
                                console.log("Encontro una iteracion");
                                let res = {
                                    Error: val.data.Error,
                                    Descripcion: val.data.Descripcion,
                                    Id: val.data.Id,
                                    Huella: val.data.Huella,
                                    HexSerie: val.data.HexSerie,
                                    Fecha: val.data.Fecha,
                                    Cn: val.data.Cn,
                                    idReferencia: van.referencia,
                                    idDocumentoFirmado: van.idDocumento,
                                    sign: van.firma,
                                    digestion: van.vector
                                };
                                responseVec.push(res);
                            }
                        });
                    });

                    return responseVec;
                } else {
                    console.error("la longitud no corresponde " + dataVector.length);
                }
            } else {
                firmav2.alertGeneral("warning", "No se logro hacer la digestion (der).");
            }

        } else {
            firmav2.alertGeneral("error", oResult.message);
        }

    }

    function signPKCS7(file, iChunkSize, iCodification, fCallbackChunk, fCallbackComplete, fCallbackError, bVector) {
        var fileSize = file.size;
        if (typeof iChunkSize == "undefined") {
            iChunkSize = 10000;
        }
        var chunkSize = iChunkSize * 1024; // bytes
        var offset = 0;
        var block = null;
        var digest = null;

        switch (iCodification) {
            case fielnetv2.Digest.MD5:
                digest = forge.md.md5.create();
                break;
            case fielnetv2.Digest.SHA1:
                digest = forge.md.sha1.create();
                break;
            case fielnetv2.Digest.SHA2:
                digest = forge.md.sha256.create();
                break;
            default:
                digest = forge.md.sha1.create();
        }

        var readBlock = function (evt) {
            if (evt.target.error == null) {
                offset += evt.target.result.byteLength;
                var binary = "";
                var bytes = new Uint8Array(evt.target.result);
                var length = bytes.length;
                for (var i = 0; i < length; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                digest.update(binary);
                if (typeof fCallbackChunk == "function") {
                    fCallbackChunk((offset * 100) / fileSize);
                }
            } else {
                if (typeof callbackError == "function") {
                    callbackError("Ha ocurrido un error leyendo archivo: " + evt.target.error);
                }
                return;
            }
            if (offset >= fileSize) {
                if (bVector) {
                    getVectorFile(forge.util.encode64(digest.digest().data), iCodification, file.name, function (oResponse) {
                        if (typeof fCallbackComplete == "function") {
                            fCallbackComplete(oResponse);
                        }

                    });
                } else {
                    signPKCS1(forge.util.encode64(digest.digest().data), iCodification, fielnetv2.Encoding.B64, function (data) {
                        data.digest = forge.util.encode64(digest.digest().data);
                        fCallbackComplete(data);
                    }, false);
                }
                return;
            }
            block(offset, chunkSize, file);
        };

        block = function (_offset, length, _file) {
            var fileReader = new FileReader();
            var blob = _file.slice(_offset, length + _offset);
            fileReader.onload = readBlock;
            fileReader.readAsArrayBuffer(blob);
        };
        block(offset, chunkSize, file);
    }
    ;

    function getFileDigest(file, iChunkSize, iAlgoritm, fCallback, fCallbackError) {
        var fileSize = file.size;
        if (typeof iChunkSize == "undefined") {
            iChunkSize = 10000;
        }
        var chunkSize = iChunkSize * 1024; // bytes
        var offset = 0;
        var block = null;
        var digest = null;

        switch (iAlgoritm) {
            case fielnetv2.Digest.MD5:
                digest = forge.md.md5.create();
                break;
            case fielnetv2.Digest.SHA1:
                digest = forge.md.sha1.create();
                break;
            case fielnetv2.Digest.SHA2:
                digest = forge.md.sha256.create();
                break;
            default:
                digest = forge.md.sha1.create();
        }

        var readBlock = function (evt) {
            if (evt.target.error == null) {
                offset += evt.target.result.byteLength;
                var binary = "";
                var bytes = new Uint8Array(evt.target.result);
                var length = bytes.length;
                for (var i = 0; i < length; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                digest.update(binary);

            } else {
                if (typeof fCallbackError == "function") {
                    fCallbackError("Ha ocurrido un error leyendo archivo: " + evt.target.error);
                }
                return;
            }
            if (offset >= fileSize) {
                if (typeof fCallback == "function") {
                    fCallback(file.name, forge.util.encode64(digest.digest().data));
                }
                return;
            }
            block(offset, chunkSize, file);
        };

        block = function (_offset, length, _file) {
            var fileReader = new FileReader();
            var blob = _file.slice(_offset, length + _offset);
            fileReader.onload = readBlock;
            fileReader.readAsArrayBuffer(blob);
        };
        block(offset, chunkSize, file);

    }

    function propertyLoaded(strProperty) {
        var loaded = true;

        switch (strProperty) {
            case "certificate":
                loaded = (strCertificate != null && typeof strCertificate == "string");
                break;
            case "key":
                loaded = (oPrivateKey != null && typeof oPrivateKey == "string");
                break;
            case "pfx":
                loaded = (strPfx != null && typeof strPfx == "string");
                break;
        }

        return loaded;

    }

    //Métodos de utilidad

    function saveInStorage(strStorage, strKey, strElement) {
        var oResult = {};
        var isPropertyLoaded = propertyLoaded(strElement);
        if (!isPropertyLoaded) {
            oResult.state = -99;
            oResult.description = "No se ha cargado el elemento deseado";
        } else {
            var strProperty = "";
            switch (strStorage) {
                case fielnetv2.Storages.LOCAL_STORAGE:
                case fielnetv2.Storages.SESSION_STORAGE:
                    break;
                default:
                    strStorage = fielnetv2.Storages.SESSION_STORAGE;
            }
            switch (strElement) {
                case "certificate":
                    strProperty = strCertificate;
                    break;
                case "key":
                    //strProperty = oPrivateKey; LINEA COMENTA A PROPOSITO IMPORTANTE
                    strProperty = strPrivateKey;
                    break;
                case "pfx":
                    strProperty = strPfx;
                    break;
            }
            if (strStorage == fielnetv2.Storages.LOCAL_STORAGE) {
                localStorage.setItem(strKey, strProperty);
            } else {
                sessionStorage.setItem(strKey, strProperty);
            }
            oResult.state = 0;
            oResult.description = "Elemento guardado correctamente";
        }
        return oResult;
    }

    function loadElementFromStorage(strStorage, strKey, strElement) {
        var oResult = {};
        var inStorage = true;
        switch (strStorage) {
            case fielnetv2.Storages.LOCAL_STORAGE:
            case fielnetv2.Storages.SESSION_STORAGE:
                break;
            default:
                inStorage = false;

        }
        if (inStorage) {
            var strItem = (strStorage == fielnetv2.Storages.LOCAL_STORAGE ? localStorage.getItem(strKey) : sessionStorage.getItem(strKey));
            if (strItem == null) {
                oResult.state = -99;
                oResult.description = "No se encontró elemento con la llave asociativa: '" + strKey + "' dentro del almacén " + (strStorage == fielnetv2.Storages.LOCAL_STORAGE ? "localStorage" : "sessionStorage");
            } else {
                switch (strElement) {
                    case "certificate":
                        strCertificate = strItem;
                        var certHex = forge.util.bytesToHex(forge.util.decode64(getCertificate()))
                        strCerPem = KJUR.asn1.ASN1Util.getPEMStringFromHex(certHex, 'CERTIFICATE');
                        break;
                    case "key":
                        strPrivateKey = strItem;
                        oPrivateKey = strPrivateKey;
                        break;
                    case "pfx":
                        strPfx = strItem;
                        break;

                }
                oResult.state = 0;
                oResult.description = "Elemento cargado correctamente";
            }
        } else {
            oResult.state = -99;
            oResult.description = "El almacén especificado '" + strStorage + "' no existe";
        }
        return oResult;
    }

    function parseObject(oData) {
        var oTransfer = {};

        for (var prop in oData) {
            eval("oTransfer." + prop + "='" + oData[prop] + "';");
        }
        return oTransfer;
    }

    function saveTransfers(oData) {
        var oResult = {};
        if (oData.length == 3) {
            if (typeof oData[0] == "object") {
                var bSaved = false;
                var strData = (oData[1] == fielnetv2.Storages.LOCAL_STORAGE ? localStorage.getItem(oData[2]) : sessionStorage.getItem(oData[2]));
                if (strData == null) {
                    var aItems = [];
                    aItems.push(parseObject(oData[0]));
                    var JSONTransfer = JSON.stringify(aItems);
                    var oStorage = (oData[1] == fielnetv2.Storages.LOCAL_STORAGE ? localStorage : sessionStorage);
                    oStorage.setItem(oData[2], JSONTransfer);
                    bSaved = true;
                } else {
                    var oStorage = (oData[1] == fielnetv2.Storages.LOCAL_STORAGE ? localStorage : sessionStorage);
                    var strData = oStorage.getItem(oData[2]);
                    var JSONItems = JSON.parse(strData);
                    //Quitamos el registro previamente realizado
                    for (var idx in JSONItems) {
                        if (JSONItems[idx].serie == oData[0].serie) {
                            JSONItems.splice(idx, 1);
                        }
                    }
                    JSONItems.push(parseObject(oData[0]));
                    oStorage.setItem(oData[2], JSON.stringify(JSONItems));
                    bSaved = true;
                }
                if (bSaved) {
                    oResult.state = 0;
                    oResult.description = "Objeto guardado correctamente";
                } else {
                    oResult.state = -98;
                    oResult.description = "Objeto no guardado";
                }
            } else {
                oResult.state = -99;
                oResult.description = "Formato de datos no válido";
            }
        }
    }

    function getTransfers(iStorage, strKey) {
        var storage = null;
        switch (iStorage) {
            case fielnetv2.Storages.LOCAL_STORAGE:
                storage = localStorage;
                break;
            case fielnetv2.Storages.SESSION_STORAGE:
                storage = sessionStorage;
                break;

        }
        if (storage == null) {
            return null;
        } else {
            try {
                return JSON.parse(storage.getItem(strKey));
            } catch (e) {
                return null;
            }
        }
    }

    function clearTransfers(iStorage, strKey) {
        var oStorage = null;
        switch (iStorage) {
            case fielnetv2.Storages.LOCAL_STORAGE:
                oStorage = localStorage;
                break;
            case fielnetv2.Storages.SESSION_STORAGE:
                oStorage = sessionStorage;
                break;

        }
        if (oStorage != null) {
            if (typeof strKey == "string") {
                oStorage.removeItem(strKey);
            } else {
                oStorage.clear();
            }
        }
    }

    function getAttributeFromSubject(certificate, strOID) {
        for (var i = 0; i < certificate.subject.attributes.length; i++) {
            if (certificate.subject.attributes[i].type == strOID) {
                var attribute = certificate.subject.attributes[i].value;
                if (certificate.subject.attributes[i].valueTagClass == 12) {
                    attribute = forge.util.decodeUtf8(attribute);
                }
                return attribute;
            }
        }
        return null;
    }

    function getCertificateAttributeFromSubject(strB64Certificate, strOID) {
        var cert = getCertificateObject(strB64Certificate);
        if (cert == null && strCertificate != null) {
            cert = getCertificateObject(strCertificate);
            strOID = strB64Certificate;
        }
        if (cert == null) {
            return null;
        }
        return getAttributeFromSubject(cert, strOID);
    }

    function getCodeAndTransfer(fCallback) {
        var curp = getCertificateAttributeFromSubject(getCertificate(), "2.5.4.5");
        ajaxRequest({
            url: CONTROLLERv2,
            method: "POST",
            async: false,
            data: "metodo=getCodeAndTransfer&curp=" + curp,
            success: function (oResponse, status, xmlhttp) {
                $("#curpFirmaE").val(curp);
                oResponse = JSON.parse(oResponse);
                codigo = oResponse.Codigo;
                transferencia = oResponse.Transferencia;
                fCallback(oResponse);

            },
            complete: function (data) {
                if (typeof fCallback == "function") {
                }
            },
            error: function (data) {
                if (typeof fCallback == "function") {
                }
            }
        });
    }

    function addExtraParameters(strUrl) {
        extraParameters = strUrl;
    }

    //Interfaz publica
    return {
        /*
         * Valida si el web browser objetos de html5 que se requieren para firma digital
         * @param strMessage en caso de que se especifique un valor para este parámetro, si el web browser
         *  no soporta html5 se despliega una ventana con el mensaje con el mensaje especificado
         * @return true| false en caso de soportar o no html5
         */
        validateWebBrowser: function (strMessage) {
            return validateWebBrowser(strMessage);
        },
        /*
         * Método encargado de realizar la lectura del certificado
         * @param Id del elemento file con el que selccionarán el certificado del usuario
         * @return
         */
        readCertificate: function (strIdElement) {
            readCertificate(strIdElement);
        },
        /*
         * Obtiene el certificado leído previamente
         * @param
         * @return Regresa el certificado codificado en base 64, en caso de que no se haya leído previamente, regresa null
         */
        getCertificate: function () {
            return getCertificate();
        },
        /*
         * Decodifica certificado
         * @param strCertificate representa el certificado codificado en base 64
         * @param bOcsp determina si se realizará consulta ocsp del certificado
         * @param fCallback función que tendrá los resultados de la operación realizada
         *  El objeto pasado como argumento a fCallback contiene las siguientes propiedades:
         *  -state código de resultado del proceso
         *  -description descripción textual del código del proceso
         *  -hexSerie Número de serie del certificado codificado en hexadecimal
         *  -notBefore Inicio de la vigencia del certificado
         *  -notAfter Fin de la vigencia del certificado
         *  -publicKey: LLave publica
         *  -fingerPrint: Huella digital del certificado
         *
         *
         *  -transfer: Identificador de la operación en el buscriptográfico
         *  -date: fecha en la que se realizó la operación
         *  -evidence: firma digital del buscriptográfico
         *
         *   PROPIETARIO
         *
         *  -subjectName: Nombre
         *  -subjectEmail: Correo electrónico
         *  -subjectOrganization: Organización a la que pertenece
         *  -subjectDepartament: Departamente a la que pertenece
         *  -subjectState: Estado donde habita
         *  -subjectCountry: País donde habita
         *  -subjectRFC: RFC
         *  -subjectCURP: CURP
         *
         *  Emisor
         *
         *  -issuerName: Nombre
         *  -issuerEmail: Correo electrónico
         *  -issuerOrganization: Organización
         *  -issuerDepartament: Departamento
         *  -issuerState: Estado
         *  -issuerCountry: País
         *  -issuerRFC : RFC
         *  -issuerCURP: CURP
         
         * @return
         */
        decodeCertificate: function (strCertificate, bOcsp, fCallback) {
            decodeCertificate(strCertificate, bOcsp, fCallback);
        },
        /*
         * Método encargado de realizar la lectura de la llave privada
         * @param Id del elemento file con el que selccionarán la llave privada del usuario
         * @return
         */
        readPrivateKey: function (strIdElement) {
            readPrivateKey(strIdElement);
        },
        /*
         * Método encargado de realizar la lectura del certificado y la llave privada del usuario
         * este método funciona como una abreviación para readCertificate() y readPrivateKey()
         * @param strIdCertificate id del elemento file que realizará la lectura del certificado
         * @param strIdPrivateKey id del elemento file que realizar la lectura de la llave privada
         * @return
         */
        readCertificateAndPrivateKey: function (strIdCertificate, strIdPrivateKey) {
            readCertificate(strIdCertificate);
            readPrivateKey(strIdPrivateKey);
        },
        /*
         * Método encargado de validar la relación entre el par de llaves proporcionados
         * @param strPass representa la frase de acceso al par de llaves
         * @fCallback función que entregará los detalles de la operación realizada
         *   El objeto que  recibe como argumento fCallback contiene 2 propiedades
         *   -state : Código de resultado
         *   -description: Descripción textual del código de resultado
         *
         * @return
         */
        validateKeyPairs: function (strPass, fCallback) {
            validateKeyPairs(strPass, fCallback);
        },
        /*
         * Método encargado de realizar la lectura del pfx
         * @param strIdElement representa el id del elemento file que realizará la carga del PFX
         * @return
         */
        readPfx: function (strIdElement) {
            readPfx(strIdElement);
        },
        /*
         * Método encargado de acceder al par de llaves del certificado
         * @param strPass representa la frase de acceso al encapsulado
         * @param fCallback función que entregará los detalles de la operación realizada
         *   El objeto que  recibe como argumento fCallback contiene 2 propiedades
         *   -state : Código de resultado
         *   -description: Descripción textual del código de resultado
         * @return
         */
        openPfx: function (strPass, fCallback) {
            openPfx(strPass, fCallback);
        },
        /*
         * Realiza la firma digital de una cadena
         * @param strText texto a firmar
         * @param iAlgoritm valor numérico que define el tipo de digestión aplicada al contenido que se firmará digitalmente
         *  Los valores para este parámetro están definidos dentro del objeto Digest y son:
         *  fielnetv2.Digest.MD5
         *  fielnetv2.Digest.SHA1
         *  fielnetv2.Digest.SHA2
         * @param iCodification tipo de codificación aplicada al contenido a firmar
         *  Los valores para este parámetro están definidos dentro del objeto Encoding y son:
         *  fielnetv2.Encoding.UTF8
         *  fielnetv2.Encoding.B64
         * @param fCallback función que entregará los detalles de la operación realizada
         *  El objeto que recibe como argumento fCallback contiene las siguientes propiedades
         *   -state: Código de resultado
         *   -description: Descripción textual del código de resultado
         *   -transfer : Id del registro en el buscriptográfico
         *   -date: Fecha en la que se realizó la operación
         *   -evidence : Firma digital del buscriptográfico
         *   -commonName: Nombre del propietario que realizó la firma
         *   -hexSerie : Número de serie en formato hexadecimal del certificado
         *   -sign: firma digital
         * @return
         */
        signPKCS1: function (strText, iAlgoritm, iCodification, fCallback) {
            signPKCS1(strText, iAlgoritm, iCodification, fCallback, false);
        },
        /*
         * Realizar firma digital de cadenas usando par de llaves
         * @param strCertificate certificado del usuario codificado en base 64
         * @param strPrivateKey llave privada codificada en base 64
         * @param strPass frase de acceso del par de llaves
         * @param strText cadena a firmar
         * @param iAlgoritm valor numérico que define el tipo de digestión aplicada al contenido que se firmará digitalmente
         *  Los valores para este parámetro están definidos dentro del objeto Digest y son:
         *  fielnetv2.Digest.MD5
         *  fielnetv2.Digest.SHA1
         *  fielnetv2.Digest.SHA2
         * @param iCodification tipo de codificación aplicada al contenido a firmar
         *  Los valores para este parámetro están definidos dentro del objeto Encoding y son:
         *  fielnetv2.Encoding.UTF8
         *  fielnetv2.Encoding.B64
         * @param fCallback función con los resultados del proceso de firma
         *  El objeto que recibe como argumento fCallback contiene las siguientes propiedades
         *   -state: Código de resultado
         *   -description: Descripción textual del código de resultado
         *   -transfer : Id del registro en el buscriptográfico
         *   -date: Fecha en la que se realizó la operación
         *   -evidence : Firma digital del buscriptográfico
         *   -commonName: Nombre del propietario que realizó la firma
         *   -hexSerie : Número de serie en formato hexadecimal del certificado
         *   -sign: firma digital
         * @return
         */
        signPKCS1WithKeyPairs: function (strCertificate, strPrivateKey, strPass, strText, iAlgoritm, iCodification, fCallback) {
            signPKCS1WithKeyPairs(strCertificate, strPrivateKey, strPass, strText, iAlgoritm, iCodification, fCallback, false);
        },
        /*
         * Realizar firma digital de cadenas usando PFX
         * @param strPfx pfx codificado en base 64
         * @param strPass frase de acceso del par de llaves
         * @param strText cadena a firmar
         * @param iAlgoritm valor numérico que define el tipo de digestión aplicada al contenido que se firmará digitalmente
         *  Los valores para este parámetro están definidos dentro del objeto Digest y son:
         *  fielnetv2.Digest.MD5
         *  fielnetv2.Digest.SHA1
         *  fielnetv2.Digest.SHA2
         * @param iCodification tipo de codificación aplicada al contenido a firmar
         *  Los valores para este parámetro están definidos dentro del objeto Encoding y son:
         *  fielnetv2.Encoding.UTF8
         *  fielnetv2.Encoding.B64
         * @param fCallback función con los resultados del proceso de firma
         *  El objeto que recibe como argumento fCallback contiene las siguientes propiedades
         *   -state: Código de resultado
         *   -description: Descripción textual del código de resultado
         *   -transfer : Id del registro en el buscriptográfico
         *   -date: Fecha en la que se realizó la operación
         *   -evidence : Firma digital del buscriptográfico
         *   -commonName: Nombre del propietario que realizó la firma
         *   -hexSerie : Número de serie en formato hexadecimal del certificado
         *   -sign: firma digital
         * @return
         */
        signPkcs1WithPfx: function (strPfx, strPass, strText, iAlgoritm, iCodification, fCallback) {
            signPkcs1WithPfx(strPfx, strPass, strText, iAlgoritm, iCodification, fCallback, false);
        },
        /*
         * Método encargado de verificar la firma digital
         * @param strCadenaOriginal cadena que fue sobre la cual se realizó la firma digital
         * @param strFirma firma codificada en base 64
         * @param strCertificate   certificado codificado en base 64
         * @param fCallback función con los resultados del proceso de verificación
         *  El objeto que recibe como argumento fCallback contiene las siguientes propiedades
         *   -state: Código de resultado
         *   -description: Descripción textual del código de resultado
         *   -transfer : Id del registro en el buscriptográfico
         *   -date: Fecha en la que se realizó la operación
         *   -evidence : Firma digital del buscriptográfico
         *   -commonName: Nombre del propietario que realizó la firma
         *   -hexSerie : Número de serie en formato hexadecimal del certificado
         *   -sign: firma digital
         * @return
         */
        verifySign: function (strCadenaOriginal, strFirma, strCertificate, iCodification, fCallback) {
            // var cadenaOriginal = (iCodification == fielnetv2.Encoding.B64 ? strCadenaOriginal : forge.util.encode64(strCadenaOriginal));
            var cadenaOriginal = (iCodification == fielnetv2.Encoding.B64 ? strCadenaOriginal : forge.util.binary.base64.encode(forge.util.text.utf8.encode(strCadenaOriginal)));

            verifySign(cadenaOriginal, strFirma, strCertificate, fCallback);
        },
        /*
         * Realiza la lectura de un archivo determinado
         * @param file representa el archivo a leer
         * @param iChunkSize valor numérico
         * @param iAlgoritm representa el tipo de digestión aplicada al contenido del archivo
         *  Los valores para este parámetro están definidos dentro del objeto Digest y son:
         *  fielnetv2.Digest.MD5
         *  fielnetv2.Digest.SHA1
         *  fielnetv2.Digest.SHA2
         * @param fCallbackComplete función que entregará los detalles del proceso de firmado
         * @param fCallbackError función que entregará los detalles del error ocurrido en la lectura del archivo
         *  El objeto que recibe como argumento fCallback contiene las siguientes propiedades
         *   -state: Código de resultado
         *   -description: Descripción textual del código de resultado
         *   -transfer : Id del registro en el buscriptográfico
         *   -date: Fecha en la que se realizó la operación
         *   -evidence : Firma digital del buscriptográfico
         *   -commonName: Nombre del propietario que realizó la firma
         *   -hexSerie : Número de serie en formato hexadecimal del certificado
         *   -sign: firma digital
         *   -digest: digestión del archivo
         * @return
         */
        signPKCS7: function (files, iChunkSize, iAlgoritm, fCallbackComplete, fCallbackError) {
            if (oPrivateKey == null) {
                if (typeof fCallbackComplete == "function") {
                    var oResult = {};
                    oResult.state = -78;
                    oResult.description = "No se ha cargado elemento para firma electrónica";
                    fCallbackComplete(oResult);
                }
                return;
            }
            getCodeAndTransfer(function (result) {
                if (result.state == 0) {
                    var totalArchivosFirmados = 0;
                    archivosFirmados = [];
                    for (var i = 0; i < files.length; i++) {
                        getFileDigest(files[i], iChunkSize, iAlgoritm, function (nombreArchivo, digestion) {
                            signPKCS1OffLine(digestion, iAlgoritm, fielnetv2.Encoding.B64, function (resultadoFirmaArchivo) {
                                var archivoFirmado = {};
                                archivoFirmado.nombre = nombreArchivo;
                                archivoFirmado.digestion = digestion;
                                archivoFirmado.firma = resultadoFirmaArchivo.sign;
                                archivosFirmados.push(archivoFirmado);
                                totalArchivosFirmados++;
                            });

                        }, fCallbackError);
                    }
                    var iInterval = setInterval(function () {
                        if (totalArchivosFirmados == files.length) {
                            clearInterval(iInterval);
                            signPKCS1OffLine(codigo, iAlgoritm, fielnetv2.Digest.UTF8, function (firmaCodigoResult) { //Firma código de activación
                                var tipoDigestion = iAlgoritm == fielnetv2.Digest.MD5 ? "MD5" : iAlgoritm == fielnetv2.Digest.SHA1 ? "SHA1" : iAlgoritm == fielnetv2.Digest.SHA2 ? "SHA256" : "SHA1";
                                var strCN = getCertificateAttributeFromSubject(getCertificate(), "2.5.4.3");
                                ajaxRequest({
                                    url: CONTROLLERv2,
                                    data: "metodo=firmaArchivo&codigo=" + codigo + "&transferencia=" + transferencia + "&cert=" + getCertificate() + "&firmaCodigo=" + firmaCodigoResult.sign + "&serie=" + getSerialNumber(getCertificate()) + "&cn=" + strCN + "&jsonData=" + JSON.stringify(archivosFirmados) + "&tipoDigestion=" + tipoDigestion,
                                    method: "POST",
                                    success: function (oResponse, status, xmlhttp) {
                                        if (typeof fCallbackComplete == "function") {
                                            var oJSONResponse = JSON.parse(oResponse);
                                            fCallbackComplete(oJSONResponse);
                                        }
                                    },
                                    error: function (data, status, xmlhttp) {
                                        if (typeof fCallbackError == "function") {
                                            fCallbackError(data);
                                        }
                                    }
                                });

                            });
                        }
                    }, 100);
                } else {
                    if (typeof fCallbackComplete == "function") {
                        fCallbackComplete(result);
                    }
                }

            });
        },
        signFilePCKS1: function (file, iChunkSize, iAlgoritm, fCallbackChunk, fCallbackComplete, fCallbackError) {
            signPKCS7(file, iChunkSize, iAlgoritm, fCallbackChunk, fCallbackComplete, fCallbackError, false);
        },
        getFileDigest: function (file, iChunkSize, iAlgoritm, fCallback, fCallbackError) {
            getFileDigest(file, iChunkSize, iAlgoritm, fCallback, fCallbackError);
        },
        /*
         * Guarda el certificado en algún almacén especificado
         * @param Valor numérico que define en que almacén se guardará el certificado
         * @param strKey 'llave' del arreglo asociativo con el que se accederá al certificado
         * @return regresa un objeto con dos propiedades
         *  state valor numérico con el código de resultado
         *  description valor de tipo cadena con los detalles del código de resultado
         *
         */
        saveCertificate: function (strStorage, strKey) {
            return saveInStorage(strStorage, strKey, 'certificate');
        },
        /*
         * Carga el certificado dentro de la instancia
         * @param Valor numérico que define de que almacén se cargará el certificado
         * @param strKey 'llave' del arreglo asociativo con el que se guardó el certificado
         * @return regresa un objeto con dos propiedades
         *  state valor numérico con el código de resultado
         *  description valor de tipo cadena con los detalles del código de resultado
         *
         */
        loadCertificate: function (strStorage, strKey) {
            return loadElementFromStorage(strStorage, strKey, 'certificate');
        },
        /*
         * Guarda la llave privada en algún almacén especificado
         *
         * Importante: Guarda encontenido del archivo .key, no la llave privada desencriptada.
         *
         * @param Valor numérico que define en que almacén se guardará la llave privada
         * @param strKey 'llave' del arreglo asociativo con el que se accederá a la llave privada
         * @return regresa un objeto con dos propiedades
         *  state valor numérico con el código de resultado
         *  description valor de tipo cadena con los detalles del código de resultado
         *
         */
        saveCertificateAndPrivateKey: function (strStorage, strKeyCertificate, strKeyPrivate) {
            var obj = {};
            obj = saveInStorage(strStorage, strKeyPrivate, 'key');
            if (obj.state == 0) {
                obj = saveInStorage(strStorage, strKeyCertificate, 'certificate');
            }

            return obj;
        },
        /*
         * Carga la llave privada dentro de la instancia
         * @param Valor numérico que define de que almacén se cargará la llave privada
         * @param strKey 'llave' del arreglo asociativo con el que se guardó la llave privada
         * @return regresa un objeto con dos propiedades
         *  state valor numérico con el código de resultado
         *  description valor de tipo cadena con los detalles del código de resultado
         *
         */
        loadCertificateAndPrivateKey: function (strStorage, strKeyCertificate, strKeyPrivateKey) {
            var obj = {};
            obj = loadElementFromStorage(strStorage, strKeyCertificate, "certificate");
            if (obj.state == 0) {
                obj = loadElementFromStorage(strStorage, strKeyPrivateKey, 'key');
            }
            return obj;
        },
        /*
         * Guarda el PFX en algún almacén especificado
         * @param Valor numérico que define en que almacén se guardará al PFX
         * @param strKey 'llave' del arreglo asociativo con el que se accederá al PFX
         * @return regresa un objeto con dos propiedades
         *  state valor numérico con el código de resultado
         *  description valor de tipo cadena con los detalles del código de resultado
         *
         */
        savePfx: function (strStorage, strKey) {
            return saveInStorage(strStorage, strKey, 'pfx');
        },
        /*
         * Carga el pfx dentro de la instancia
         * @param Valor numérico que define de que almacén se cargará el pfx
         * @param strKey 'llave' del arreglo asociativo con el que se guardó el pfx
         * @return regresa un objeto con dos propiedades
         *  state valor numérico con el código de resultado
         *  description valor de tipo cadena con los detalles del código de resultado
         */
        loadPfx: function (strStorage, strKey) {
            return loadElementFromStorage(strStorage, strKey, 'pfx');
        },
        /*
         * Define el tipo de evidencias a generar
         * @param iEvidence
         * cuando es 0 no se Genera TSA ni NOM
         * cuando es 1 Sólo se genera TSA
         * cuando es 2 Sólo se genera NOM
         * Con cualquier otro valor se genera tanto TSA como NOM
         *
         */
        setEvidences: function (iEvidence) {
            if (!isNaN(iEvidence)) {
                evidence = iEvidence;
            } else {
                evidence = fielnetv2.Evidences.NONE;
            }
        },
        saveTransfers: function () {
            saveTransfers(arguments);
        },
        getTransfers: function (iStorage, strKey) {
            return getTransfers(iStorage, strKey);
        },
        clearTransfers: function (iStorage, strKey) {
            clearTransfers(iStorage, strKey);
        },
        setReferencia: function (strReferencia) {
            setReferencia(strReferencia);
        },

        /*
         * Método encargado de firmar digestiones de archivos
         * @param strId, corresponde al id del elemento que contiene los datos en formato json que se firmarán
         * @param iAlgoritm, tipo de digestión a aplicar
         * @param jwtToken El token de sesion
         * @param fCallback, función que contendrá los datos del proceso de firma
         */
        signFileDigestv2: async function (strId, iAlgoritm, extraParams, jwtToken, fCallback) {
            var oResult = {};
            if (oPrivateKey == null) {
                if (typeof fCallback == "function") {
                    oResult.state = -78;
                    oResult.description = "No se ha cargado elemento para firma electrónica";
                    fCallback(oResult);
                }
                return;
            }
            var oElement = document.getElementById(strId);
            var base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
            if (oElement) {
                try {
                    let digestionesArchivos = JSON.parse(oElement.value);//proporcionar digestion
                    console.info(digestionesArchivos);
                    let digestiones = digestionesArchivos;
                    if (digestiones) {
                        //console.info("pass log 1 => " + digestiones.length);
                        let archivosFirmados = [];
                        let auxForVector = [];
                        for (var idx = 0; idx < digestiones.length; idx++) {
                            //console.info("pass log  2 " + idx);
                            let documentoFirma = digestiones[idx];
                            let nombreDocumento = documentoFirma.documento;
                            let digestionDocumento = documentoFirma.digestion;
                            if (!base64regex.test(digestionDocumento)) {
                                console.warn("Digestión no válida: " + digestionDocumento);
                                // continue;
                            }
                            //console.info("Digestión válida: " + digestionDocumento);
                            //funciones que estaban entro de getVectorFile
                            let oDate = new Date();
                            let strDate = oDate.getFullYear().toString().substring(2) + "" + padding(oDate.getMonth().toString()) + "" + padding(oDate.getDate().toString()) + "" + padding(oDate.getHours().toString()) + "" + padding(oDate.getMinutes().toString()) + "" + padding(oDate.getSeconds().toString()) + "Z";
                            let length = forge.util.decode64(digestionDocumento).length;
                            //console.info("pass log  2 " + idx + "=> switch");
                            switch (length) {
                                case 16:
                                    iAlgoritm = fielnetv2.Digest.MD5;
                                    break;
                                case 20:
                                    iAlgoritm = fielnetv2.Digest.SHA1;
                                    break;
                                case 32:
                                    iAlgoritm = fielnetv2.Digest.SHA2;
                                    break;
                                default:
                                    iAlgoritm = fielnetv2.Digest.SHA1;
                            }
                            // console.info("pass log  2 " + idx + "=> auxVec");
                            let auxVec = {
                                digestionDocumento: digestionDocumento.replace('=', ''),
                                fecha: strDate,
                                idDocumentosFirmados: documentoFirma.idDocumentosFirmados,
                                idReferencia: documentoFirma.idReferencia
                            };


                            auxForVector.push(auxVec);
                            //console.info("pass log  2 " + idx + "=> push");
                        }
                        console.info("Armar arreglo para obtener vectores");
                        console.info(auxForVector);
                        // Una vez creado el arreglo con las digestiones, pasamos todo a el metodo der
                        let response = await getVectorFilev2(auxForVector, iAlgoritm, extraParams, jwtToken, function (response) {
                            console.error(response);
                        });

                        console.info("Termino el getVectorFilev2");
                        if (response.length != 0) {
                            let curp = getCertificateAttributeFromSubject(getCertificate(), "2.5.4.5");
                            let strCN = getCertificateAttributeFromSubject(getCertificate(), "2.5.4.3");

                            const firmaData = {
                                debugg: extraParams.debugg,
                                cveAdscripcion: extraParams.cveAdscripcion,
                                cert: getCertificate(),
                                serie: getSerialNumber(),
                                cn: strCN,
                                curpFirmante: curp,
                                jsonData: response,
                                extraParams: {
                                    cveAdscripcion: extraParams.cveAdscripcion,
                                    cveTipoDocumentoFirma: extraParams.cveTipoDocumentoFirma,
                                    cveGrupo: extraParams.cveGrupo,
                                    validCurp: 0
                                },
                                cveGrupo: extraParams.cveGrupo,
                            };

                            const firmaResponse = await fetch('http://localhost/api/firma-electronica/firma-archivos-extendido', {
                                method: 'POST',
                                body: JSON.stringify(firmaData),
                                headers: {
                                    'Content-Type': 'application/json',
                                    'sessionData': jwtToken
                                }
                            });

                            const oJSONResponse = await firmaResponse.json();

                            if (typeof fCallback == "function") {
                                fCallback(oJSONResponse);
                            }

                            // ajaxRequest({
                            //     url: CONTROLLERv2,
                            //     data: "accion=firmaArchivosExtendido&debugg=" + firmav2.debugg + "&cveAdscripcion=" + firmav2.cveAdscripcion + "&cert=" + getCertificate() + "&serie=" + getSerialNumber(getCertificate()) + "&cn=" + strCN + "&jsonData=" + JSON.stringify(response) + "" + "&curpFirmante=" + curp + "&extraParams=" + JSON.stringify(firmav2.extraParams),
                            //     method: "POST",
                            //     success: function (oResponse, status, xmlhttp) {
                            //
                            //     },
                            //     error: function (data, status, xmlhttp) {
                            //         if (typeof fCallback == "function") {
                            //             fCallback(data);
                            //         }
                            //     }
                            // });

                        } else {
                            oResult.state = -75;
                            oResult.description = "Ocurrio un Error al procesar los datos " + response.descripcion;
                        }

                    } else {
                        oResult.state = -75;
                        oResult.description = "No hay datos que procesar";
                    }
                } catch (e) {
                    oResult.state = -77;
                    oResult.description = "Error en la cadena de datos";
                }
            } else {
                oResult.state = -76;
                oResult.description = "Elemento cuyo id: " + strId + " no existe";
            }
            // if (typeof fCallback == "function") {
            //     fCallback(oResult);
            // }
        },

        addExtraParameters: function (strUrl) {
            //if (typeof strUrl == "string") {
            //  if (strUrl.indexOf("&") == -1) {
            //    strUrl = "&" + strUrl;
            //}
            addExtraParameters(strUrl);
            return true;
            //}
            //return false;
        },
        getFechasCertificado: function () {
            try {
                var certDerBytes = forge.util.decode64(getCertificate());
                var obj = forge.asn1.fromDer(certDerBytes);
                var cert = forge.pki.certificateFromAsn1(obj);
                var dateFin = cert.validity.notAfter;
                var dateIni = cert.validity.notBefore;

                var objDates = {};
                var objDates = {
                    fechaInicial: dateIni.getTime(),
                    fechaFinal: dateFin.getTime()
                };

                return objDates;

            } catch (e) {
                console.error("Se murio getFechasCertificado() :(");
                console.error(e);
                return null;
            }
        }
    }
})();
