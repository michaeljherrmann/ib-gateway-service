/*
 * This an implementation of OCRA - OATH Challenge-Response Algorithm
 * based on ocra java reference implementation
 * from https://tools.ietf.org/html/rfc6287
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

// to test
// https://su12147fct0:12002/ocrajs/index.html

const jsSHA = require("jssha");

var OCRA = {

   // Convert a hex string to a byte array
   hexStr2Bytes : function(hex)
   {
       for (var bytes = [], c = 0; c < hex.length; c += 2)
       bytes.push(parseInt(hex.substr(c, 2), 16));
       return bytes;
   },

   // Convert a byte array to a hex string
   bytesToHexStr : function(bytes)
   {
       for (var hex = [], i = 0; i < bytes.length; i++) {
	   hex.push((bytes[i] >>> 4).toString(16));
	   hex.push((bytes[i] & 0xF).toString(16));
       }
       return hex.join("");
   },

   // convert ArrayBuffer to String
   ab2str : function (buf)
   {
     return String.fromCharCode.apply(null, new Uint8Array(buf));
   },

   // convert String to Uint8 ArrayBuffer View
   convertStringToArrayBufferView : function(str)
   {
     if (typeof str === 'string' || str instanceof String)
     {
       var bytes = new Uint8Array(str.length);
       for (var iii = 0; iii < str.length; iii++)
       {
	   bytes[iii] = str.charCodeAt(iii);
       }

       return bytes;
     }
     else
       return str;
   },

   // convert String to ArrayBuffer
   str2ab : function(str) {
     if (typeof str === 'string' || str instanceof String)
     {
     var buf = new ArrayBuffer(str.length);
     var bufView = new Uint8Array(buf);
     for (var i=0, strLen=str.length; i<strLen; i++) {
       bufView[i] = str.charCodeAt(i);
     }
     return bufView;
     }
     else
        return null;
   },

   // append ArrayBuffer to existing ArrayBuffer
   ArrayConcat : function(buffer1, buffer2)
   {
      var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
      tmp.set(new Uint8Array(buffer1), 0);
      tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
      return tmp.buffer;
   },

   // hmac_hash with Web Cryptography API
   // https://www.w3.org/TR/WebCryptoAPI/
   //
   // this api are supported on chrome 49+, firefox 47+, edge, and ms prefix old version on ie11
   // http://caniuse.com/#feat=cryptography
   //
   // based on sample from https://jswebcrypto.azurewebsites.net/demo.html#/hmac
   // and http://qnimate.com/digital-signature-using-web-cryptography-api/
   hmacAsyncWeb_hash : function(hashAlgo, hashKey, hashText,codeDigits)
   {
     var hmacSha = {name: 'HMAC', hash: {name: hashAlgo.toUpperCase()}};

     if (typeof hashKey === 'string' || hashKey instanceof String)
       var hmacKeyBuf = this.convertStringToArrayBufferView(hashKey);
     else
       var hmacKeyBuf = hashKey;

     if (typeof hashText === 'string' || hashText instanceof String)
       var hmacTextBuf = this.convertStringToArrayBufferView(hashText);
     else
       var hmacTextBuf = hashText;

     var crypto = window.crypto || window.msCrypto;

     return crypto.subtle.importKey("raw", hmacKeyBuf, hmacSha, false, ["sign", "verify"])
     .then(function(cryptokey){
        return crypto.subtle.sign({name: 'HMAC'}, cryptokey, hmacKeyBuf);
     },
     function(err){
        console.log(err);
     })
     .then(function(hash) {
       // put selected bytes into result int
       var offset = hash[hash.byteLength - 1] & 0xf;

       var binary =
         ((hash[offset + 0] & 0x7f) << 24) |
         ((hash[offset + 1] & 0xff) << 16) |
         ((hash[offset + 2] & 0xff) << 8) |
         (hash[offset + 3] & 0xff);

       var otp = binary % DIGITS_POWER[codeDigits];

       var result = otp.toString();
       while (result.length < codeDigits) {
         result = "0" + result;
       }
       return Promise.resolve(result);
     });
   },

   // hmac using standford crypto lib
   // https://github.com/bitwiseshiftleft/sjcl
   hmacsjcl_hash : function(hashAlgo, hashKey, hashText)
   {
     if (typeof hashKey === 'string' || hashKey instanceof String)
       var hmacKeyBuf = sjcl.codec.utf8String.toBits(hashKey);
     else
       var hmacKeyBuf = sjcl.codec.arrayBuffer.toBits(hashKey.buffer);

     if (typeof hashText === 'string' || hashText instanceof String)
       var hashText = sjcl.codec.utf8String.toBits(hashText);
     else
       var hashText = sjcl.codec.arrayBuffer.toBits(hashText.buffer);

     var hashfunction = null;

     if(hashAlgo.toUpperCase() == "SHA-1") hashfunction = sjcl.hash.sha1;
     else if(hashAlgo.toUpperCase() == "SHA-256") hashfunction = sjcl.hash.sha256;
     else if(hashAlgo.toUpperCase() == "SHA-512") hashfunction = sjcl.hash.sha512;

     var out = (new sjcl.misc.hmac(hmacKeyBuf, hashfunction)).mac(hashText);
     var hmac = new Uint8Array(sjcl.codec.arrayBuffer.fromBits(out));
     return hmac;
   },

   hmacjssha_hash : function(hashAlgo, hashKey, hashText)
   {
     if (typeof hashKey === 'string' || hashKey instanceof String)
       var hmacKeyBuf = this.convertStringToArrayBufferView(hashKey);
     else
       var hmacKeyBuf = hashKey;

     if (typeof hashText === 'string' || hashText instanceof String)
       var hmacTextBuf = this.convertStringToArrayBufferView(hashText);
     else
       var hmacTextBuf = hashText;


     var shaObj = new jsSHA(hashAlgo, "ARRAYBUFFER");
     shaObj.setHMACKey(hmacKeyBuf, "ARRAYBUFFER");
     shaObj.update(hmacTextBuf);
     return shaObj.getHMAC("ARRAYBUFFER");
   },

   // OCRA method
   getOCRAmsg : function(ocraSuite, counter, question, password, sessionInformation, timeStamp)
   {
     var codeDigits = 0;
     var crypto = "";
     var result = null;
     var ocraSuiteLength = ocraSuite.length;
     var counterLength = 0;
     var questionLength = 0;
     var passwordLength = 0;
     var sessionInformationLength = 0;
     var timeStampLength = 0;

     // The OCRASuites components
     var CryptoFunction = ocraSuite.split(":")[1];
     var DataInput = ocraSuite.split(":")[2];

     if(CryptoFunction.toLowerCase().indexOf("sha1") > 1) crypto = "SHA-1";
     else if(CryptoFunction.toLowerCase().indexOf("sha256") > 1) crypto = "SHA-256";
     else if(CryptoFunction.toLowerCase().indexOf("sha512") > 1) crypto = "SHA-512";
     else {
       console.log("SHA algorithme unknow \"" + CryptoFunction + "\"");
       return null;
     }

     // How many digits should we return
     codeDigits = parseInt(CryptoFunction.substring(CryptoFunction.lastIndexOf("-")+1));

     // The size of the byte array message to be encrypted
     // Counter
     if(DataInput.toLowerCase().startsWith("c")) {
       // Fix the length of the HEX string
       while(counter.length < 16)
         counter = "0" + counter;
       counterLength=8;
     }

     // Question - always 128 bytes
     if(DataInput.toLowerCase().startsWith("q") ||
         (DataInput.toLowerCase().indexOf("-q") >= 0)) {
       while(question.length < 256)
         question = question + "0";
       questionLength=128;
     }


     // Password - sha1
     if(DataInput.toLowerCase().indexOf("psha1") > 1){
       passwordLength=20;
     }

     // Password - sha256
     if(DataInput.toLowerCase().indexOf("psha256") > 1){
       passwordLength=32;
     }

     // Password - sha512
     if(DataInput.toLowerCase().indexOf("psha512") > 1){
       passwordLength=64;
     }

     // sessionInformation - s064
     if(DataInput.toLowerCase().indexOf("s064") > 1){
       while(sessionInformation.length < 128)
         sessionInformation = "0" + sessionInformation;
       sessionInformationLength=64;
     }

     // sessionInformation - s128
     if(DataInput.toLowerCase().indexOf("s128") > 1){
       while(sessionInformation.length < 256)
         sessionInformation = "0" + sessionInformation;
       sessionInformationLength=128;
     }

     // sessionInformation - s256
     if(DataInput.toLowerCase().indexOf("s256") > 1){
       while(sessionInformation.length < 512)
         sessionInformation = "0" + sessionInformation;
       sessionInformationLength=256;
     }

     // sessionInformation - s512
     if(DataInput.toLowerCase().indexOf("s512") > 1){
       while(sessionInformation.length < 1024)
         sessionInformation = "0" + sessionInformation;
       sessionInformationLength=512;
     }

     // TimeStamp
     if(DataInput.toLowerCase().startsWith("t") ||
         (DataInput.toLowerCase().indexOf("-t") > 1)){
       while(timeStamp.length < 16)
         timeStamp = "0" + timeStamp;
       timeStampLength=8;
     }

     // create a new array of Uint8Array with lenght of all zone
     // Remember to add "1" for the "00" byte delimiter
     var msgArrayBuffer = new ArrayBuffer(ocraSuiteLength +
         counterLength +
         questionLength +
         passwordLength +
         sessionInformationLength +
         timeStampLength +
         1);

     // creat view of ab
     var msg = new Uint8Array(msgArrayBuffer);

     // Put the bytes of "ocraSuite" parameters into the message
     var bArray = this.str2ab(ocraSuite);
     for (var i=0;i<bArray.length;i++)
       msg [i] = bArray[i];

     // Delimiter
     msg[bArray.length] = 0x00;

     // Put the bytes of "Counter" to the message
     // Input is HEX encoded
     if(counterLength > 0 ){
       bArray = this.hexStr2Bytes(counter);
       for (var i=0;i<bArray.length;i++)
         msg [i + ocraSuiteLength + 1] = bArray[i];
     }

     // Put the bytes of "question" to the message
     // Input is text encoded
     if(questionLength > 0 ){
       bArray = this.hexStr2Bytes(question);
       for (var i=0;i<bArray.length;i++)
         msg [i + ocraSuiteLength + 1 + counterLength] = bArray[i];
     }

     // Put the bytes of "password" to the message
     // Input is HEX encoded
     if(passwordLength > 0){
       bArray = this.hexStr2Bytes(password);
       for (var i=0;i<bArray.length;i++)
         msg [i + ocraSuiteLength + 1 + counterLength + questionLength] = bArray[i];
     }

     // Put the bytes of "sessionInformation" to the message
     // Input is text encoded
     if(sessionInformationLength > 0 ){
       bArray = this.hexStr2Bytes(sessionInformation);
       for (var i=0;i<bArray.length;i++)
         msg [i + ocraSuiteLength + 1 + counterLength + questionLength + passwordLength] = bArray[i];
     }

     // Put the bytes of "time" to the message
     // Input is text value of minutes
     if(timeStampLength > 0){
       bArray = this.hexStr2Bytes(timeStamp);
       for (var i=0;i<bArray.length;i++)
         msg [i + ocraSuiteLength + 1 + counterLength + questionLength + passwordLength + sessionInformationLength] = bArray[i];
     }

     return { msg: new Uint8Array(msg), hashmethod: crypto, codedigits: codeDigits};
   },

   genOCRAResult: function(hash,codeDigits) {
     // OCRA size modulo : 0 1 2 3 4 5 6 7 8
     var DIGITS_POWER = [1,10,100,1000,10000,100000,1000000,10000000,100000000];

     // put selected bytes into result int
     var offset = hash[hash.byteLength - 1] & 0xf;

     var binary =
       ((hash[offset + 0] & 0x7f) << 24) |
       ((hash[offset + 1] & 0xff) << 16) |
       ((hash[offset + 2] & 0xff) << 8) |
       (hash[offset + 3] & 0xff);

     var otp = binary % DIGITS_POWER[codeDigits];

     var result = otp.toString();
     while (result.length < codeDigits) {
       result = "0" + result;
     }
     return result;
   },

   generateOCRA : function(ocraSuite, key, counter, question, password, sessionInformation, timeStamp, cryptoEngine = "jsSHA")
   {
     var result=this.getOCRAmsg(ocraSuite, counter, question, password, sessionInformation, timeStamp);
     var crypto  = result.hashmethod;
     var msgBuff = result.msg;
     var codeDigits = result.codedigits;
     var keyBuff = new Uint8Array(this.hexStr2Bytes(key));

     if (cryptoEngine==="jsSHA")
     var hash = this.hmacjssha_hash(crypto, keyBuff, msgBuff);
     else if (cryptoEngine==="sjcl")
     var hash = this.hmacsjcl_hash(crypto, keyBuff, msgBuff);
     if (hash==null) return null;

     return this.genOCRAResult(hash,codeDigits);
   },

   // return promise
   // use then function to get result
   generateOCRAasync : function(ocraSuite, key, counter, question, password, sessionInformation, timeStamp)
   {
     var result=this.getOCRAmsg(ocraSuite, counter, question, password, sessionInformation, timeStamp);
     var crypto  = result.hashmethod;
     var msgBuff = result.msg;
     var codeDigits = result.codedigits;
     var keyBuff = new Uint8Array(this.hexStr2Bytes(key));

     return this.hmacAsyncWeb_hash(crypto, keyBuff, msgBuff,codeDigits);
   }
}

module.exports = OCRA;
