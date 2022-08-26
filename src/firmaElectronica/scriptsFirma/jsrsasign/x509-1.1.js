/*! x509-1.1.6.js (c) 2012-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/* 
 * x509.js - X509 class to read subject public key from certificate.
 *
 * Copyright (c) 2010-2015 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name x509-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version x509 1.1.6 (2015-May-20)
 * @since jsrsasign 1.x.x
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/*
 * Depends:
 *   base64.js
 *   rsa.js
 *   asn1hex.js
 */

/**
 * X.509 certificate class.<br/>
 * @class X.509 certificate class
 * @property {RSAKey} subjectPublicKeyRSA Tom Wu's RSAKey object
 * @property {String} subjectPublicKeyRSA_hN hexadecimal string for modulus of RSA public key
 * @property {String} subjectPublicKeyRSA_hE hexadecimal string for public exponent of RSA public key
 * @property {String} hex hexacedimal string for X.509 certificate.
 * @author Kenji Urushima
 * @version 1.0.1 (08 May 2012)
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 */
function X509() {
    this.subjectPublicKeyRSA = null;
    this.subjectPublicKeyRSA_hN = null;
    this.subjectPublicKeyRSA_hE = null;
    this.hex = null;

    // ===== get basic fields from hex =====================================

    /**
     * get hexadecimal string of serialNumber field of certificate.<br/>
     * @name getSerialNumberHex
     * @memberOf X509#
     * @function
     */
    this.getSerialNumberHex = function() {
        return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1]);
    };

    /**
     * get hexadecimal string of issuer field TLV of certificate.<br/>
     * @name getIssuerHex
     * @memberOf X509#
     * @function
     */
    this.getIssuerHex = function() {
        return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]);
    };

    /**
     * get string of issuer field of certificate.<br/>
     * @name getIssuerString
     * @memberOf X509#
     * @function
     */
    this.getIssuerString = function() {
        return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]));
    };

    /**
     * get hexadecimal string of subject field of certificate.<br/>
     * @name getSubjectHex
     * @memberOf X509#
     * @function
     */
    this.getSubjectHex = function() {
        return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]);
    };

	this.getVersionNumber=function(){
		return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0,[0,5,5]);
		
	};
	this.getRFC=function(){
		return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0,[0,5,4]);
	};
	this.getCurp=function(){
			return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0,[0,5,5]);
	
	};
    /**
     * get string of subject field of certificate.<br/>
     * @name getSubjectString
     * @memberOf X509#
     * @function
     */
    this.getSubjectString = function() {
        return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]));
    };

    /**
     * get notBefore field string of certificate.<br/>
     * @name getNotBefore
     * @memberOf X509#
     * @function
     */
    this.getNotBefore = function() {
        var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]);
        s = s.replace(/(..)/g, "%$1");
        s = decodeURIComponent(s);
        return s;
    };

    /**
     * get notAfter field string of certificate.<br/>
     * @name getNotAfter
     * @memberOf X509#
     * @function
     */
    this.getNotAfter = function() {
        var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]);
        s = s.replace(/(..)/g, "%$1");
        s = decodeURIComponent(s);
        return s;
    };

    // ===== read certificate public key ==========================

    // ===== read certificate =====================================
    /**
     * read PEM formatted X.509 certificate from string.<br/>
     * @name readCertPEM
     * @memberOf X509#
     * @function
     * @param {String} sCertPEM string for PEM formatted X.509 certificate
     */
    this.readCertPEM = function(sCertPEM) {
        var hCert = X509.pemToHex(sCertPEM);
        var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
        var rsa = new RSAKey();
        rsa.setPublic(a[0], a[1]);
        this.subjectPublicKeyRSA = rsa;
        this.subjectPublicKeyRSA_hN = a[0];
        this.subjectPublicKeyRSA_hE = a[1];
        this.hex = hCert;
    };

    this.readCertPEMWithoutRSAInit = function(sCertPEM) {
        var hCert = X509.pemToHex(sCertPEM);
        var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
        this.subjectPublicKeyRSA.setPublic(a[0], a[1]);
        this.subjectPublicKeyRSA_hN = a[0];
        this.subjectPublicKeyRSA_hE = a[1];
        this.hex = hCert;
    };
};

X509.pemToBase64 = function(sCertPEM) {
    var s = sCertPEM;
    s = s.replace("-----BEGIN CERTIFICATE-----", "");
    s = s.replace("-----END CERTIFICATE-----", "");
    s = s.replace(/[ \n]+/g, "");
    return s;
};

X509.pemToHex = function(sCertPEM) {
    var b64Cert = X509.pemToBase64(sCertPEM);
    var hCert = b64tohex(b64Cert);
    return hCert;
};

// NOTE: Without BITSTRING encapsulation.
X509.getSubjectPublicKeyPosFromCertHex = function(hCert) {
    var pInfo = X509.getSubjectPublicKeyInfoPosFromCertHex(hCert);
    if (pInfo == -1) return -1;    
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pInfo); 
    if (a.length != 2) return -1;
    var pBitString = a[1];
    if (hCert.substring(pBitString, pBitString + 2) != '03') return -1;
    var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hCert, pBitString);
    
    if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
    return pBitStringV + 2;
};

// NOTE: privateKeyUsagePeriod field of X509v2 not supported.
// NOTE: v1 and v3 supported
X509.getSubjectPublicKeyInfoPosFromCertHex = function(hCert) {
    var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pTbsCert); 
    if (a.length < 1) return -1;
    if (hCert.substring(a[0], a[0] + 10) == "a003020102") { // v3
        if (a.length < 6) return -1;
        return a[6];
    } else {
        if (a.length < 5) return -1;
        return a[5];
    }
};

X509.getPublicKeyHexArrayFromCertHex = function(hCert) {
    var p = X509.getSubjectPublicKeyPosFromCertHex(hCert);
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p); 
    if (a.length != 2) return [];
    var hN = ASN1HEX.getHexOfV_AtObj(hCert, a[0]);
    var hE = ASN1HEX.getHexOfV_AtObj(hCert, a[1]);
    if (hN != null && hE != null) {
        return [hN, hE];
    } else {
        return [];
    }
};

X509.getHexTbsCertificateFromCert = function(hCert) {
    var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
    return pTbsCert;
};

X509.getPublicKeyHexArrayFromCertPEM = function(sCertPEM) {
    var hCert = X509.pemToHex(sCertPEM);
    var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
    return a;
};

X509.hex2dn = function(hDN) {
    var s = "";
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hDN, 0);
    for (var i = 0; i < a.length; i++) {
        var hRDN = ASN1HEX.getHexOfTLV_AtObj(hDN, a[i]);
        s = s + "/" + X509.hex2rdn(hRDN);
    }
    return s;
};

X509.hex2rdn = function(hRDN) {
    var hType = ASN1HEX.getDecendantHexTLVByNthList(hRDN, 0, [0, 0]);
    var hValue = ASN1HEX.getDecendantHexVByNthList(hRDN, 0, [0, 1]);
    var type = "";
    try { type = X509.DN_ATTRHEX[hType]; } catch (ex) { type = hType; }
    hValue = hValue.replace(/(..)/g, "%$1");
    var value = decodeURIComponent(hValue);
    return type + "=" + value;
};

X509.DN_ATTRHEX = {
    "0603550406": "C",
    "060355040a": "O",
    "060355040b": "OU",
    "0603550403": "CN",
    "0603550405": "SN",
    "0603550408": "ST",
    "0603550407": "L",
	"06092a864886f70d010901":"E",
	"0603550409":"STREET",
	"0603550411":"PostalCode",
	"06092a864886f70d010902":"Autorizo"
};

/**
 * get RSAKey/ECDSA public key object from PEM certificate string
 * @name getPublicKeyFromCertPEM
 * @memberOf X509
 * @function
 * @param {String} sCertPEM PEM formatted RSA/ECDSA/DSA X.509 certificate
 * @return returns RSAKey/KJUR.crypto.{ECDSA,DSA} object of public key
 * @since x509 1.1.1
 * @description
 * NOTE: DSA is also supported since x509 1.1.2.
 */
X509.getPublicKeyFromCertPEM = function(sCertPEM) {
    var info = X509.getPublicKeyInfoPropOfCertPEM(sCertPEM);

    if (info.algoid == "2a864886f70d010101") { // RSA
        var aRSA = KEYUTIL.parsePublicRawRSAKeyHex(info.keyhex);
        var key = new RSAKey();
        key.setPublic(aRSA.n, aRSA.e);
        return key;
    } else if (info.algoid == "2a8648ce3d0201") { // ECC
        var curveName = KJUR.crypto.OID.oidhex2name[info.algparam];
        var key = new KJUR.crypto.ECDSA({'curve': curveName, 'info': info.keyhex});
        key.setPublicKeyHex(info.keyhex);
        return key;
    } else if (info.algoid == "2a8648ce380401") { // DSA 1.2.840.10040.4.1
        var p = ASN1HEX.getVbyList(info.algparam, 0, [0], "02");
        var q = ASN1HEX.getVbyList(info.algparam, 0, [1], "02");
        var g = ASN1HEX.getVbyList(info.algparam, 0, [2], "02");
        var y = ASN1HEX.getHexOfV_AtObj(info.keyhex, 0);
        y = y.substr(2);
        var key = new KJUR.crypto.DSA();
        key.setPublic(new BigInteger(p, 16),
                      new BigInteger(q, 16),
                      new BigInteger(g, 16),
                      new BigInteger(y, 16));
        return key;
    } else {
        throw "unsupported key";
    }
};

/**
 * get public key information from PEM certificate
 * @name getPublicKeyInfoPropOfCertPEM
 * @memberOf X509
 * @function
 * @param {String} sCertPEM string of PEM formatted certificate
 * @return {Hash} hash of information for public key
 * @since x509 1.1.1
 * @description
 * Resulted associative array has following properties:
 * <ul>
 * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
 * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
 * <li>keyhex - hexadecimal string of key in the certificate</li>
 * </ul>
 * @since x509 1.1.1
 */
X509.getPublicKeyInfoPropOfCertPEM = function(sCertPEM) {
    var result = {};
    result.algparam = null;
    var hCert = X509.pemToHex(sCertPEM);

    // 1. Certificate ASN.1
    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); 
    if (a1.length != 3)
        throw "malformed X.509 certificate PEM (code:001)"; // not 3 item of seq Cert

    // 2. tbsCertificate
    if (hCert.substr(a1[0], 2) != "30")
        throw "malformed X.509 certificate PEM (code:002)"; // tbsCert not seq 

    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); 

    // 3. subjectPublicKeyInfo
    if (a2.length < 7)
        throw "malformed X.509 certificate PEM (code:003)"; // no subjPubKeyInfo

    var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[6]); 

    if (a3.length != 2)
        throw "malformed X.509 certificate PEM (code:004)"; // not AlgId and PubKey

    // 4. AlgId
    var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]); 

    if (a4.length != 2)
        throw "malformed X.509 certificate PEM (code:005)"; // not 2 item in AlgId

    result.algoid = ASN1HEX.getHexOfV_AtObj(hCert, a4[0]);

    if (hCert.substr(a4[1], 2) == "06") { // EC
        result.algparam = ASN1HEX.getHexOfV_AtObj(hCert, a4[1]);
    } else if (hCert.substr(a4[1], 2) == "30") { // DSA
        result.algparam = ASN1HEX.getHexOfTLV_AtObj(hCert, a4[1]);
    }

    // 5. Public Key Hex
    if (hCert.substr(a3[1], 2) != "03")
        throw "malformed X.509 certificate PEM (code:006)"; // not bitstring

    var unusedBitAndKeyHex = ASN1HEX.getHexOfV_AtObj(hCert, a3[1]);
    result.keyhex = unusedBitAndKeyHex.substr(2);

    return result;
};

/**
 * get position of subjectPublicKeyInfo field from HEX certificate
 * @name getPublicKeyInfoPosOfCertHEX
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of certificate
 * @return {Integer} position in hexadecimal string
 * @since x509 1.1.4
 * @description
 * get position for SubjectPublicKeyInfo field in the hexadecimal string of
 * certificate.
 */
X509.getPublicKeyInfoPosOfCertHEX = function(hCert) {
    // 1. Certificate ASN.1
    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); 
    if (a1.length != 3)
        throw "malformed X.509 certificate PEM (code:001)"; // not 3 item of seq Cert

    // 2. tbsCertificate
    if (hCert.substr(a1[0], 2) != "30")
        throw "malformed X.509 certificate PEM (code:002)"; // tbsCert not seq 

    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); 

    // 3. subjectPublicKeyInfo
    if (a2.length < 7)
        throw "malformed X.509 certificate PEM (code:003)"; // no subjPubKeyInfo
    
    return a2[6];
};

/**
 * get array of X.509 V3 extension value information in hex string of certificate
 * @name getV3ExtInfoListOfCertHex
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Array} array of result object by {@link X509.getV3ExtInfoListOfCertHex}
 * @since x509 1.1.5
 * @description
 * This method will get all extension information of a X.509 certificate.
 * Items of resulting array has following properties:
 * <ul>
 * <li>posTLV - index of ASN.1 TLV for the extension. same as 'pos' argument.</li>
 * <li>oid - dot noted string of extension oid (ex. 2.5.29.14)</li>
 * <li>critical - critical flag value for this extension</li>
 * <li>posV - index of ASN.1 TLV for the extension value.
 * This is a position of a content of ENCAPSULATED OCTET STRING.</li>
 * </ul>
 * @example
 * hCert = X509.pemToHex(certGithubPEM);
 * a = X509.getV3ExtInfoListOfCertHex(hCert);
 * // Then a will be an array of like following:
 * [{posTLV: 1952, oid: "2.5.29.35", critical: false, posV: 1968},
 *  {posTLV: 1974, oid: "2.5.29.19", critical: true, posV: 1986}, ...]
 */
X509.getV3ExtInfoListOfCertHex = function(hCert) {
    // 1. Certificate ASN.1
    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); 
    if (a1.length != 3)
        throw "malformed X.509 certificate PEM (code:001)"; // not 3 item of seq Cert

    // 2. tbsCertificate
    if (hCert.substr(a1[0], 2) != "30")
        throw "malformed X.509 certificate PEM (code:002)"; // tbsCert not seq 

    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); 

    // 3. v3Extension EXPLICIT Tag [3]
    // ver, seri, alg, iss, validity, subj, spki, (iui,) (sui,) ext
    if (a2.length < 8)
        throw "malformed X.509 certificate PEM (code:003)"; // tbsCert num field too short

    if (hCert.substr(a2[7], 2) != "a3")
        throw "malformed X.509 certificate PEM (code:004)"; // not [3] tag

    var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[7]);
    if (a3.length != 1)
        throw "malformed X.509 certificate PEM (code:005)"; // [3]tag numChild!=1

    // 4. v3Extension SEQUENCE
    if (hCert.substr(a3[0], 2) != "30")
        throw "malformed X.509 certificate PEM (code:006)"; // not SEQ

    var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]);

    // 5. v3Extension item position
    var numExt = a4.length;
    var aInfo = new Array(numExt);
    for (var i = 0; i < numExt; i++) {
	aInfo[i] = X509.getV3ExtItemInfo_AtObj(hCert, a4[i]);
    }
    return aInfo;
};

/**
 * get X.509 V3 extension value information at the specified position
 * @name getV3ExtItemInfo_AtObj
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @param {Integer} pos index of hexadecimal string for the extension
 * @return {Object} properties for the extension
 * @since x509 1.1.5
 * @description
 * This method will get some information of a X.509 V extension 
 * which is referred by an index of hexadecimal string of X.509 
 * certificate. 
 * Resulting object has following properties:
 * <ul>
 * <li>posTLV - index of ASN.1 TLV for the extension. same as 'pos' argument.</li>
 * <li>oid - dot noted string of extension oid (ex. 2.5.29.14)</li>
 * <li>critical - critical flag value for this extension</li>
 * <li>posV - index of ASN.1 TLV for the extension value.
 * This is a position of a content of ENCAPSULATED OCTET STRING.</li>
 * </ul>
 * This method is used by {@link X509.getV3ExtInfoListOfCertHex} internally.
 */
X509.getV3ExtItemInfo_AtObj = function(hCert, pos) {
    var info = {};

    // posTLV - extension TLV
    info.posTLV = pos;

    var a  = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pos);
    if (a.length != 2 && a.length != 3)
        throw "malformed X.509v3 Ext (code:001)"; // oid,(critical,)val

    // oid - extension OID
    if (hCert.substr(a[0], 2) != "06")
        throw "malformed X.509v3 Ext (code:002)"; // not OID "06"
    var valueHex = ASN1HEX.getHexOfV_AtObj(hCert, a[0]);
    info.oid = ASN1HEX.hextooidstr(valueHex); 

    // critical - extension critical flag
    info.critical = false; // critical false by default
    if (a.length == 3) info.critical = true;

    // posV - content TLV position of encapsulated
    //        octet string of V3 extension value.
    var posExtV = a[a.length - 1];
    if (hCert.substr(posExtV, 2) != "04")
        throw "malformed X.509v3 Ext (code:003)"; // not EncapOctet "04"
    info.posV = ASN1HEX.getStartPosOfV_AtObj(hCert, posExtV);
    
    return info;
};

/**
 * get X.509 V3 extension value ASN.1 TLV for specified oid or name
 * @name getHexOfTLV_V3ExtValue
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @param {String} oidOrName oid or name for extension (ex. 'keyUsage' or '2.5.29.15')
 * @return {String} hexadecimal string of extension ASN.1 TLV
 * @since x509 1.1.6
 * @description
 * This method will get X.509v3 extension value of ASN.1 TLV
 * which is specifyed by extension name or oid. 
 * @example
 * hExtValue = X509.getHexOfTLV_V3ExtValue(hCert, "keyUsage");
 * // hExtValue will be such like '030205a0'.
 */
X509.getHexOfTLV_V3ExtValue = function(hCert, oidOrName) {
    var pos = X509.getPosOfTLV_V3ExtValue(hCert, oidOrName);
    if (pos == -1) return '';
    return ASN1HEX.getHexOfTLV_AtObj(hCert, pos);
};

/**
 * get X.509 V3 extension value ASN.1 V for specified oid or name
 * @name getHexOfV_V3ExtValue
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @param {String} oidOrName oid or name for extension (ex. 'keyUsage' or '2.5.29.15')
 * @return {String} hexadecimal string of extension ASN.1 TLV
 * @since x509 1.1.6
 * @description
 * This method will get X.509v3 extension value of ASN.1 value
 * which is specifyed by extension name or oid. 
 * If there is no such extension in the certificate,
 * it returns empty string (i.e. '').
 * Available extension names and oids are defined
 * in the {@link KJUR.asn1.x509.OID} class.
 * @example
 * hExtValue = X509.getHexOfV_V3ExtValue(hCert, "keyUsage");
 * // hExtValue will be such like '05a0'.
 */
X509.getHexOfV_V3ExtValue = function(hCert, oidOrName) {
    var pos = X509.getPosOfTLV_V3ExtValue(hCert, oidOrName);
    if (pos == -1) return '';
    return ASN1HEX.getHexOfV_AtObj(hCert, pos);
};

/**
 * get index in the certificate hexa string for specified oid or name specified extension
 * @name getPosOfTLV_V3ExtValue
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @param {String} oidOrName oid or name for extension (ex. 'keyUsage' or '2.5.29.15')
 * @return {Integer} index in the hexadecimal string of certficate for specified extension
 * @since x509 1.1.6
 * @description
 * This method will get X.509v3 extension value of ASN.1 V(value)
 * which is specifyed by extension name or oid. 
 * If there is no such extension in the certificate,
 * it returns empty string (i.e. '').
 * Available extension names and oids are defined
 * in the {@link KJUR.asn1.x509.OID} class.
 * @example
 * idx = X509.getPosOfV_V3ExtValue(hCert, "keyUsage");
 * // The 'idx' will be index in the string for keyUsage value ASN.1 TLV.
 */
X509.getPosOfTLV_V3ExtValue = function(hCert, oidOrName) {
    var oid = oidOrName;
    if (! oidOrName.match(/^[0-9.]+$/)) oid = KJUR.asn1.x509.OID.name2oid(oidOrName);
    if (oid == '') return -1;

    var infoList = X509.getV3ExtInfoListOfCertHex(hCert);
    for (var i = 0; i < infoList.length; i++) {
	var info = infoList[i];
	if (info.oid == oid) return info.posV;
    }
    return -1;
};

X509.KEYUSAGE_NAME = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly"
];

/**
 * get KeyUsage extension value as binary string in the certificate
 * @name getExtKeyUsageBin
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {String} binary string of key usage bits (ex. '101')
 * @since x509 1.1.6
 * @description
 * This method will get key usage extension value
 * as binary string such like '101'.
 * Key usage bits definition is in the RFC 5280.
 * If there is no key usage extension in the certificate,
 * it returns empty string (i.e. '').
 * @example
 * bKeyUsage = X509.getExtKeyUsageBin(hCert);
 * // bKeyUsage will be such like '101'.
 * // 1 - digitalSignature 
 * // 0 - nonRepudiation
 * // 1 - keyEncipherment
 */
X509.getExtKeyUsageBin = function(hCert) {
    var hKeyUsage = X509.getHexOfV_V3ExtValue(hCert, "keyUsage");
    if (hKeyUsage == '') return '';
    if (hKeyUsage.length % 2 != 0 || hKeyUsage.length <= 2)
	throw "malformed key usage value";
    var unusedBits = parseInt(hKeyUsage.substr(0, 2));
    var bKeyUsage = parseInt(hKeyUsage.substr(2), 16).toString(2);
    return bKeyUsage.substr(0, bKeyUsage.length - unusedBits);
};

/**
 * get KeyUsage extension value as names in the certificate
 * @name getExtKeyUsageString
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {String} comma separated string of key usage
 * @since x509 1.1.6
 * @description
 * This method will get key usage extension value
 * as comma separated string of usage names.
 * If there is no key usage extension in the certificate,
 * it returns empty string (i.e. '').
 * @example
 * sKeyUsage = X509.getExtKeyUsageString(hCert);
 * // sKeyUsage will be such like 'digitalSignature,keyEncipherment'.
 */
X509.getExtKeyUsageString = function(hCert) {
    var bKeyUsage = X509.getExtKeyUsageBin(hCert);
    var a = new Array();
    for (var i = 0; i < bKeyUsage.length; i++) {
	if (bKeyUsage.substr(i, 1) == "1") a.push(X509.KEYUSAGE_NAME[i]);
    }
    return a.join(",");
};

/**
 * get AuthorityInfoAccess extension value in the certificate as associative array
 * @name getExtAIAInfo
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Object} associative array of AIA extension properties
 * @since x509 1.1.6
 * @description
 * This method will get authority info access value
 * as associate array which has following properties:
 * <ul>
 * <li>ocsp - array of string for OCSP responder URL</li>
 * <li>caissuer - array of string for caIssuer value (i.e. CA certificates URL)</li>
 * </ul>
 * If there is no key usage extension in the certificate,
 * it returns null;
 * @example
 * oAIA = X509.getExtAIAInfo(hCert);
 * // result will be such like:
 * // oAIA.ocsp = ["http://ocsp.foo.com"];
 * // oAIA.caissuer = ["http://rep.foo.com/aaa.p8m"];
 */
X509.getExtAIAInfo = function(hCert) {
    var result = {};
    result.ocsp = [];
    result.caissuer = [];
    var pos1 = X509.getPosOfTLV_V3ExtValue(hCert, "authorityInfoAccess");
    if (pos1 == -1) return null;
    if (hCert.substr(pos1, 2) != "30") // extnValue SEQUENCE
	throw "malformed AIA Extn Value";
    
    var posAccDescList = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pos1);
    for (var i = 0; i < posAccDescList.length; i++) {
	var p = posAccDescList[i];
	var posAccDescChild = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p);
	if (posAccDescChild.length != 2)
	    throw "malformed AccessDescription of AIA Extn";
	var pOID = posAccDescChild[0];
	var pName = posAccDescChild[1];
	if (ASN1HEX.getHexOfV_AtObj(hCert, pOID) == "2b06010505073001") {
	    if (hCert.substr(pName, 2) == "86") {
		result.ocsp.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(hCert, pName)));
	    }
	}
	if (ASN1HEX.getHexOfV_AtObj(hCert, pOID) == "2b06010505073002") {
	    if (hCert.substr(pName, 2) == "86") {
		result.caissuer.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(hCert, pName)));
	    }
	}
    }
    return result;
};

function getKeyFromPlainPrivatePKCS8Hex(prvKeyHex) {
    var p8 = parsePlainPrivatePKCS8Hex(prvKeyHex);
    if (p8.algoid == "2a864886f70d010101") {
        parsePrivateRawRSAKeyHexAtObj(prvKeyHex, p8);
        var k = p8.key;
        var key = new RSAKey();
        key.setPrivateEx(k.n, k.e, k.d, k.p, k.q, k.dp, k.dq, k.co);
        return key
    } else if (p8.algoid == "2a8648ce3d0201") {
        this.parsePrivateRawECKeyHexAtObj(prvKeyHex, p8);
        if (KJUR.crypto.OID.oidhex2name[p8.algparam] === undefined) throw "KJUR.crypto.OID.oidhex2name undefined: " + p8.algparam;
        var curveName = KJUR.crypto.OID.oidhex2name[p8.algparam];
        var key = new KJUR.crypto.ECDSA({
            'curve': curveName
        });
        key.setPublicKeyHex(p8.pubkey);
        key.setPrivateKeyHex(p8.key);
        key.isPublic = false;
        return key
    } else if (p8.algoid == "2a8648ce380401") {
        var hP = ASN1HEX.getVbyList(prvKeyHex, 0, [1, 1, 0], "02");
        var hQ = ASN1HEX.getVbyList(prvKeyHex, 0, [1, 1, 1], "02");
        var hG = ASN1HEX.getVbyList(prvKeyHex, 0, [1, 1, 2], "02");
        var hX = ASN1HEX.getVbyList(prvKeyHex, 0, [2, 0], "02");
        var biP = new BigInteger(hP, 16);
        var biQ = new BigInteger(hQ, 16);
        var biG = new BigInteger(hG, 16);
        var biX = new BigInteger(hX, 16);
        var key = new KJUR.crypto.DSA();
        key.setPrivate(biP, biQ, biG, null, biX);
        return key
    } else {
        throw "unsupported private key algorithm"
    }
}
function parsePrivateRawRSAKeyHexAtObj(pkcs8PrvHex, info) {
    var keyIdx = info.keyidx;
    if (pkcs8PrvHex.substr(keyIdx, 2) != "30") throw "malformed RSA private key(code:001)";
    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, keyIdx);
    if (a1.length != 9) throw "malformed RSA private key(code:002)";
    info.key = {};
    info.key.n = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[1]);
    info.key.e = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[2]);
    info.key.d = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[3]);
    info.key.p = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[4]);
    info.key.q = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[5]);
    info.key.dp = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[6]);
    info.key.dq = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[7]);
    info.key.co = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[8])
}
function obtenLlaveDerivada(info, passcode) {
    var pbkdf2SaltWS = CryptoJS.enc.Hex.parse(info.pbkdf2Salt);
    var pbkdf2Iter = info.pbkdf2Iter;
    var pbkdf2KeyWS;
    var hmacSHA1 = function(key) {
        var hasher = new sjcl.misc.hmac(key, sjcl.hash.sha1);
        this.encrypt = function() {
            return hasher.encrypt.apply(hasher, arguments)
        }
    };
    var sjclSalt = sjcl.codec.hex.toBits(info.pbkdf2Salt);
    if (info.encryptionSchemeAlg == "DES" || info.encryptionSchemeAlg == "TripleDES") {
        pbkdf2KeyWS = sjcl.misc.pbkdf2(passcode, sjclSalt, pbkdf2Iter, 192, hmacSHA1)
    } else if (info.encryptionSchemeAlg == "AES-256") {
        pbkdf2KeyWS = sjcl.misc.pbkdf2(passcode, sjclSalt, pbkdf2Iter, 256, hmacSHA1)
    } else if (info.encryptionSchemeAlg == "AES-128") {
        pbkdf2KeyWS = sjcl.misc.pbkdf2(passcode, sjclSalt, pbkdf2Iter, 128, hmacSHA1)
    } else if (info.encryptionSchemeAlg == "AES-192") {
        pbkdf2KeyWS = sjcl.misc.pbkdf2(passcode, sjclSalt, pbkdf2Iter, 192, hmacSHA1)
    } else if (info.encryptionSchemeAlg == "RC2") {
        pbkdf2KeyWS = sjcl.misc.pbkdf2(passcode, sjclSalt, pbkdf2Iter, info.tamLlave, hmacSHA1)
    } else throw "Algoritmo no soportado";
    var pbkdf2KeyHex = sjcl.codec.hex.fromBits(pbkdf2KeyWS);
    return pbkdf2KeyHex
}
function obtieneLlavePrivada(pkcs8DER, passcode) {
    var decWS;
    var info = obtieneInfoPKCS8(pkcs8DER);
    var pbkdf2KeyHex = obtenLlaveDerivada(info, passcode);
    var encrypted = {};
    encrypted.ciphertext = CryptoJS.enc.Hex.parse(info.ciphertext);
    var pbkdf2KeyWS = CryptoJS.enc.Hex.parse(pbkdf2KeyHex);
    var IVWS = CryptoJS.enc.Hex.parse(info.encryptionSchemeIV);
    if (info.encryptionSchemeAlg === "TripleDES") decWS = CryptoJS.TripleDES.decrypt(encrypted, pbkdf2KeyWS, {
        iv: IVWS
    });
    else if (info.encryptionSchemeAlg === "DES") decWS = CryptoJS.DES.decrypt(encrypted, pbkdf2KeyWS, {
        iv: IVWS
    });
    else if (info.encryptionSchemeAlg === "AES-128" || info.encryptionSchemeAlg === "AES-192" || info.encryptionSchemeAlg === "AES-256") decWS = CryptoJS.AES.decrypt(encrypted, pbkdf2KeyWS, {
        iv: IVWS
    });
    else if (info.encryptionSchemeAlg === "RC2") {
        var effectiveKey = CryptoJS.enc.Hex.parse(info.effectiveKey);
        decWS = CryptoJS.RC2.decrypt(encrypted, pbkdf2KeyWS, {
            effectiveKeyBits: info.effectiveKey,
            iv: IVWS
        });
        var decHex = CryptoJS.enc.Hex.stringify(decWS);
        decWS = CryptoJS.RC2.decrypt(encrypted, pbkdf2KeyWS, {
            effectiveKeyBits: effectiveKey,
            iv: IVWS
        });
        var decHex = CryptoJS.enc.Hex.stringify(decWS);
        decWS = CryptoJS.RC2.decrypt(encrypted, pbkdf2KeyWS, {
            iv: IVWS
        });
        var decHex = CryptoJS.enc.Hex.stringify(decWS);
        decWS = CryptoJS.RC2.decrypt(encrypted, pbkdf2KeyWS, {
            effectiveKeyBits: 40,
            iv: IVWS
        });
        var decHex = CryptoJS.enc.Hex.stringify(decWS);
        decWS = CryptoJS.RC2.decrypt(encrypted, pbkdf2KeyWS, {
            effectiveKeyBits: 160,
            iv: IVWS
        });
        var decHex = CryptoJS.enc.Hex.stringify(decWS);
        decWS = CryptoJS.RC2.decrypt(encrypted, pbkdf2KeyWS, {
            effectiveKeyBits: 120,
            iv: IVWS
        });
        var decHex = CryptoJS.enc.Hex.stringify(decWS);
        decWS = CryptoJS.RC2.decrypt(encrypted, pbkdf2KeyWS, {
            effectiveKeyBits: 58,
            iv: IVWS
        });
        var decHex = CryptoJS.enc.Hex.stringify(decWS);
        decWS = CryptoJS.RC2.decrypt(encrypted, pbkdf2KeyWS, {
            effectiveKeyBits: effectiveKey
        })
    }
    var decHex = CryptoJS.enc.Hex.stringify(decWS);
    return decHex
}
function obtieneInfoPKCS8(sHEX) {
    var info = {};
    var a0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, 0);
    if (a0.length != 2) throw "malformed format: SEQUENCE(0).items != 2: " + a0.length;
    info.ciphertext = ASN1HEX.getHexOfV_AtObj(sHEX, a0[1]);
    var a0_0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0[0]);
    if (a0_0.length != 2) throw "malformed format: SEQUENCE(0.0).items != 2: " + a0_0.length;
    var x = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0[0]);
    if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0[0]) != "2A864886F70D01050D") throw "this only supports pkcs5PBES2";
    var a0_0_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0[1]);
    if (a0_0.length != 2) throw "malformed format: SEQUENCE(0.0.1).items != 2: " + a0_0_1.length;
    var a0_0_1_0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1[0]);
    if (a0_0_1_0.length != 2) throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + a0_0_1_0.length;
    var a0_0_1_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1[1]);
    if (a0_0_1_1.length != 2) throw "malformed format: SEQUENCE(0.0.1.1).items != 2: " + a0_0_1_1.length;
    var algoritmo = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1[0]);
    if (algoritmo === "2A864886F70D0307" || algoritmo === "3ECE45092C62A8B9") info.encryptionSchemeAlg = "TripleDES";
    else if (algoritmo === "2B0E030207") info.encryptionSchemeAlg = "DES";
    else if (algoritmo === "608648016503040116") info.encryptionSchemeAlg = "AES-192";
    else if (algoritmo === "608648016503040102") info.encryptionSchemeAlg = "AES-128";
    else if (algoritmo === "60864801650304012A") info.encryptionSchemeAlg = "AES-256";
    else if (algoritmo === "2A864886F70D0302") info.encryptionSchemeAlg = "RC2";
    else throw "Algortimo no soportado " + algoritmo; if (info.encryptionSchemeAlg !== "RC2") info.encryptionSchemeIV = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1[1]);
    else {
        var a0_0_1_1_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1_1[1]);
        info.effectiveKey = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1_1[0]);
        info.encryptionSchemeIV = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1_1[1])
    }
    var x1 = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0[0]);
    if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0[0]) != "2A864886F70D01050C") throw "this only supports pkcs5PBKDF2";
    var a0_0_1_0_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1_0[1]);
    if (a0_0_1_0_1.length < 2) throw "malformed format: SEQUENCE(0.0.1.0.1).items < 2: " + a0_0_1_0_1.length;
    info.pbkdf2Salt = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[0]);
    var iterNumHex = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[1]);
    try {
        info.pbkdf2Iter = parseInt(iterNumHex, 16)
    } catch (ex) {
        throw "malformed format pbkdf2Iter: " + iterNumHex
    }
    if (info.encryptionSchemeAlg === "RC2") {
        var tamLlave_ = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[2]);
        try {
            info.tamLlave = parseInt(tamLlave_, 16)
        } catch (ex) {
            throw "malformed format tamLlave: " + tamLlave_
        }
    }
    return info
}
function parsePlainPrivatePKCS8Hex(pkcs8PrvHex) {
    var result = {};
    result.algparam = null;
    if (pkcs8PrvHex.substr(0, 2) != "30") throw "malformed plain PKCS8 private key(code:001)";
    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, 0);
    if (a1.length != 3) throw "malformed plain PKCS8 private key(code:002)";
    if (pkcs8PrvHex.substr(a1[1], 2) != "30") throw "malformed PKCS8 private key(code:003)";
    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, a1[1]);
    if (a2.length != 2) throw "malformed PKCS8 private key(code:004)";
    if (pkcs8PrvHex.substr(a2[0], 2) != "06") throw "malformed PKCS8 private key(code:005)";
    result.algoid = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a2[0]);
    if (pkcs8PrvHex.substr(a2[1], 2) == "06") {
        result.algparam = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a2[1])
    }
    if (pkcs8PrvHex.substr(a1[2], 2) != "04") throw "malformed PKCS8 private key(code:006)";
    result.keyidx = ASN1HEX.getStartPosOfV_AtObj(pkcs8PrvHex, a1[2]);
    return result
}

/*
  X509.prototype.readCertPEM = _x509_readCertPEM;
  X509.prototype.readCertPEMWithoutRSAInit = _x509_readCertPEMWithoutRSAInit;
  X509.prototype.getSerialNumberHex = _x509_getSerialNumberHex;
  X509.prototype.getIssuerHex = _x509_getIssuerHex;
  X509.prototype.getSubjectHex = _x509_getSubjectHex;
  X509.prototype.getIssuerString = _x509_getIssuerString;
  X509.prototype.getSubjectString = _x509_getSubjectString;
  X509.prototype.getNotBefore = _x509_getNotBefore;
  X509.prototype.getNotAfter = _x509_getNotAfter;
*/
 