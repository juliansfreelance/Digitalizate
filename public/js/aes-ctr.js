/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* AES (CTR) implementación en JavaScript                       (c) Julio Calderón, Zharick Alba  */
/*                                                                                          2022  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
import Aes from './aes.js';

/**
 *
 * Esto encripta una cadena Unicode para producir un texto cifrado en base64 usando AES de 128/192/256 bits,
 * y la inversa para descifrar un texto cifrado.
 */
class AesCtr extends Aes {

    /**
     * Encriptar un texto utilizando la encriptación AES en el modo de funcionamiento Contador.
     *
     * Carácter multibyte Unicode seguro.
     *
     * @param   {string} plaintext - Texto plano origen a encriptar.
     * @param   {string} password  - La contraseña que se utilizará para generar una clave para el cifrado.
     * @param   {number} nBits - Número de bits a utilizar en la clave; 128 / 192 / 256.
     * @returns {string} Texto cifrado, codificado en base-64.
     *
     * @example
     *   const encr = AesCtr.encrypt('big secret', 'pāşšŵōřđ', 256); // 'lwGl66VVwVObKIr6of8HVqJr'
     */


    static encrypt(plaintext, password, nBits) {
        if (![128, 192, 256].includes(nBits)) throw new Error('El tamaño de la clave no es 128 / 192 / 256');
        plaintext = AesCtr.utf8Encode(String(plaintext));
        password = AesCtr.utf8Encode(String(password));

        // utilizar el propio AES para encriptar la contraseña y obtener la clave de cifrado
        // (utilizando la contraseña sin formato como fuente para la expansión de la clave)
        // para darnos una clave bien encriptada (en el uso real se podría utilizar la contraseña con hash para la clave)
        const nBytes = nBits / 8; // sin bytes en la llave (16/24/32)
        const pwBytes = new Array(nBytes);
        for (let i = 0; i < nBytes; i++) { // utilizar los primeros 16/24/32 caracteres de la contraseña para la clave
            pwBytes[i] = i < password.length ? password.charCodeAt(i) : 0;
        }
        let key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes)); // nos da una clave de 16 bytes
        key = key.concat(key.slice(0, nBytes - 16)); // ampliar la clave a 16/24/32 bytes de longitud

        // inicializar los primeros 8 bytes del bloque del contador con nonce (NIST SP 800-38A §B.2): [0-1] = milisegundo,
        // [2-3] = aleatorio, [4-7] = segundos, lo que proporciona una unicidad completa por debajo de los milisegundos hasta Feb 2106
        const timestamp = (new Date()).getTime(); // milisegundos desde el 1 de enero de 1970
        const nonceMs = timestamp%1000;
        const nonceSec = Math.floor(timestamp/1000);
        const nonceRnd = Math.floor(Math.random()*0xffff);
        // para la depuración: const [ nonceMs, nonceSec, nonceRnd ] = [ 0, 0, 0 ];
        const counterBlock = [ // Matriz de 16 bytes; el tamaño del bloque se fija en 16 para AES
            nonceMs  & 0xff, nonceMs >>>8 & 0xff,
            nonceRnd & 0xff, nonceRnd>>>8 & 0xff,
            nonceSec & 0xff, nonceSec>>>8 & 0xff, nonceSec>>>16 & 0xff, nonceSec>>>24 & 0xff,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // y convertir el nonce en una cadena que irá al frente del texto cifrado
        const nonceStr = counterBlock.slice(0, 8).map(i => String.fromCharCode(i)).join('');

        // convertir (utf-8) texto plano a matriz de bytes
        const plaintextBytes = plaintext.split('').map(ch => ch.charCodeAt(0));

        // ------------ realizar la encriptación ------------
        const ciphertextBytes = AesCtr.nistEncryption(plaintextBytes, key, counterBlock);

        // convertir una matriz de bytes en una cadena de texto cifrado (utf-8)
        const ciphertextUtf8 = ciphertextBytes.map(i => String.fromCharCode(i)).join('');

        // codificar en base-64 el texto cifrado
        const ciphertextB64 =  AesCtr.base64Encode(nonceStr+ciphertextUtf8);

        return ciphertextB64;
    }

    /**
     * El NIST SP 800-38A establece recomendaciones para los modos de funcionamiento de los cifrados 
     * en bloque en términos de operaciones de bytes. Esto implementa el modo de contador §6.5 (CTR).
     *
     *     Oⱼ = CIPHₖ(Tⱼ)      for j = 1, 2 … n
     *     Cⱼ = Pⱼ ⊕ Oⱼ        for j = 1, 2 … n-1
     *     C*ₙ = P* ⊕ MSBᵤ(Oₙ) final (partial?) block
     *   where CIPHₖ is the forward cipher function, O output blocks, P plaintext blocks, C
     *   ciphertext blocks
     *
     * @param   {number[]} plaintext - Plaintext to be encrypted, as byte array.
     * @param   {number[]} key - Key to be used to encrypt plaintext.
     * @param   {number[]} counterBlock - Initial 16-byte CTR counter block (with nonce & 0 counter).
     * @returns {number[]} Ciphertext as byte array.
     *
     * @private
     */
    static nistEncryption(plaintext, key, counterBlock) {
        const blockSize = 16; // block size fixed at 16 bytes / 128 bits (Nb=4) for AES

        // generate key schedule - an expansion of the key into distinct Key Rounds for each round
        const keySchedule = Aes.keyExpansion(key);

        const blockCount = Math.ceil(plaintext.length/blockSize);
        const ciphertext = new Array(plaintext.length);

        for (let b=0; b<blockCount; b++) {
            // ---- encrypt counter block; Oⱼ = CIPHₖ(Tⱼ) ----
            const cipherCntr = Aes.cipher(counterBlock, keySchedule);

            // block size is reduced on final block
            const blockLength = b<blockCount-1 ? blockSize : (plaintext.length-1)%blockSize + 1;

            // ---- xor plaintext with ciphered counter byte-by-byte; Cⱼ = Pⱼ ⊕ Oⱼ ----
            for (let i=0; i<blockLength; i++) {
                ciphertext[b*blockSize + i] = cipherCntr[i] ^ plaintext[b*blockSize + i];
            }

            // increment counter block (counter in 2nd 8 bytes of counter block, big-endian)
            counterBlock[blockSize-1]++;
            // and propagate carry digits
            for (let i=blockSize-1; i>=8; i--) {
                counterBlock[i-1] += counterBlock[i] >> 8;
                counterBlock[i] &= 0xff;
            }

            // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
            if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
                if (b%1000 == 0) self.postMessage({ progress: b/blockCount });
            }
        }

        return ciphertext;
    }


    /**
     * Decrypt a text encrypted by AES in counter mode of operation.
     *
     * @param   {string} ciphertext - Cipher text to be decrypted.
     * @param   {string} password - Password to use to generate a key for decryption.
     * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
     * @returns {string} Decrypted text
     *
     * @example
     *   const decr = AesCtr.decrypt('lwGl66VVwVObKIr6of8HVqJr', 'pāşšŵōřđ', 256); // 'big secret'
     */
    static decrypt(ciphertext, password, nBits) {
        if (![ 128, 192, 256 ].includes(nBits)) throw new Error('Key size is not 128 / 192 / 256');
        ciphertext = AesCtr.base64Decode(String(ciphertext));
        password = AesCtr.utf8Encode(String(password));

        // use AES to encrypt password (mirroring encrypt routine)
        const nBytes = nBits/8; // no bytes in key
        const pwBytes = new Array(nBytes);
        for (let i=0; i<nBytes; i++) { // use 1st nBytes chars of password for key
            pwBytes[i] = i<password.length ?  password.charCodeAt(i) : 0;
        }
        let key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));
        key = key.concat(key.slice(0, nBytes-16)); // expand key to 16/24/32 bytes long

        // recover nonce from 1st 8 bytes of ciphertext into 1st 8 bytes of counter block
        const counterBlock = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
        for (let i=0; i<8; i++) counterBlock[i] = ciphertext.charCodeAt(i);

        // convert ciphertext to byte array (skipping past initial 8 bytes)
        const ciphertextBytes = new Array(ciphertext.length-8);
        for (let i=8; i<ciphertext.length; i++) ciphertextBytes[i-8] = ciphertext.charCodeAt(i);

        // ------------ perform decryption ------------
        const plaintextBytes = AesCtr.nistDecryption(ciphertextBytes, key, counterBlock);

        // convert byte array to (utf-8) plaintext string
        const plaintextUtf8 = plaintextBytes.map(i => String.fromCharCode(i)).join('');

        // decode from UTF8 back to Unicode multi-byte chars
        const plaintext = AesCtr.utf8Decode(plaintextUtf8);

        return plaintext;
    }

    /**
     * NIST SP 800-38A sets out recommendations for block cipher modes of operation in terms of byte
     * operations. This implements the §6.5 Counter Mode (CTR).
     *
     *     Oⱼ = CIPHₖ(Tⱼ)      for j = 1, 2 … n
     *     Pⱼ = Cⱼ ⊕ Oⱼ        for j = 1, 2 … n-1
     *     P*ₙ = C* ⊕ MSBᵤ(Oₙ) final (partial?) block
     * donde CIPHₖ es la función de cifrado hacia adelante, O bloques de salida, C bloques de texto cifrado, 
     * P bloques de texto plano
     *
     * @param   {number[]} ciphertext - Texto cifrado a descifrar, como matriz de bytes.
     * @param   {number[]} key - Clave que se utilizará para descifrar el texto cifrado.
     * @param   {number[]} counterBlock - Bloque inicial del contador CTR de 16 bytes (con nonce y contador 0).
     * @returns {number[]} Texto plano como matriz de bytes.
     *
     * @private
     */
    static nistDecryption(ciphertext, key, counterBlock) {
        const blockSize = 16; // tamaño de bloque fijado en 16 bytes / 128 bits (Nb=4) para AES

        // generar un programa de claves - una expansión de la clave en distintas rondas de claves para cada ronda
        const keySchedule = Aes.keyExpansion(key);

        const blockCount = Math.ceil(ciphertext.length/blockSize);
        const plaintext = new Array(ciphertext.length);

        for (let b=0; b<blockCount; b++) {
            // ---- descifrar el bloque del contador; Oⱼ = CIPHₖ(Tⱼ) ----
            const cipherCntr = Aes.cipher(counterBlock, keySchedule);

            // el tamaño del bloque se reduce en el último bloque
            const blockLength = b<blockCount-1 ? blockSize : (ciphertext.length-1)%blockSize + 1;

            // ---- xor texto cifrado con contador cifrado byte a byte; Pⱼ = Cⱼ ⊕ Oⱼ ----
            for (let i=0; i<blockLength; i++) {
                plaintext[b*blockSize + i] = cipherCntr[i] ^ ciphertext[b*blockSize + i];
            }

            // incrementa el bloque de contadores (contador en los segundos 8 bytes del bloque de contadores, big-endian)
            counterBlock[blockSize-1]++;
            // y propagar los dígitos de arrastre
            for (let i=blockSize-1; i>=8; i--) {
                counterBlock[i-1] += counterBlock[i] >> 8;
                counterBlock[i] &= 0xff;
            }

            // isi en el web worker, anunciar el progreso cada 1000 bloques (aproximadamente cada 50ms)
            if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
                if (b%1000 == 0) self.postMessage({ progress: b/blockCount });
            }
        }

        return plaintext;
    }


    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


    /**
     * Codifica la cadena multibyte a utf8.
     *
     * Tenga en cuenta que utf8Encode es una función de identidad con cadenas ascii de 7 bits, pero no con cadenas de 8 bits;
     * utf8Encode('x') = 'x', but utf8Encode('ça') = 'Ã§a', and utf8Encode('Ã§a') = 'ÃÂ§a'.
     */
    static utf8Encode(str) {
        try {
            return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { // ¿No hay TextEncoder disponible?
            return unescape(encodeURIComponent(str));
        }
    }

    /**
     * Decodifica la cadena utf8 a multibyte.
     */
    static utf8Decode(str) {
        try {
            return new TextEncoder().decode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { // ¿No hay TextEncoder disponible?
            return decodeURIComponent(escape(str));
        }
    }

    /*
     * Codifica la cadena como base-64.
     */
    static base64Encode(str) {
        if (typeof btoa != 'undefined') return btoa(str); // navegador
        if (typeof Buffer != 'undefined') return new Buffer(str, 'binary').toString('base64'); // Node.js
        throw new Error('Sin codificación Base64');
    }

    /*
     * Decodes base-64 encoded string.
     */
    static base64Decode(str) {
        if (typeof atob != 'undefined') return atob(str); // navegador
        if (typeof Buffer != 'undefined') return new Buffer(str, 'base64').toString('binary'); // Node.js
        throw new Error('Sin decodificación Base64');
    }

}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

export default AesCtr;
