import AesCtr from './aes-ctr.js';
const criptoBtn = document.querySelector('.criptoBtn');
const resetCriptoBtn = document.querySelector('.resetCriptoBtn');
const cleanCriptoBtn = document.querySelector('.cleanCriptoBtn');

const loaderCripto = document.querySelector('.loaderCripto');
const respuestaCripto = document.querySelector('.respuestaCripto');
const erroraDescripto = document.querySelector('.erroraDescripto');

const errorNBits = document.querySelector('.errorNBits');
const errorPassword = document.querySelector('.errorPassword');
const errorPlaintxt = document.querySelector('.errorPlaintxt');
//----------------------------------------------------------------
const decifrarBtn = document.querySelector('.decifrarBtn');
const cleanDescifrarBtn = document.querySelector('.cleanDescifrarBtn');

const loaderDescripto = document.querySelector('.loaderDescripto');
const respuestaDescripto = document.querySelector('.respuestaDescripto');

const errorNBitsDC = document.querySelector('.errorNBitsDC');
const errorPasswordDC = document.querySelector('.errorPasswordDC');
const errorPlaintxtDC = document.querySelector('.errorPlaintxtDC');
//----------------------------------------------------------------

document.addEventListener('DOMContentLoaded', function (event) {
    document.querySelector('#claveCifrado').oninput = function () {
        const password = document.querySelector('#claveCifrado').value;
        const plaintxt = document.querySelector('#textoPlano').value;
        if (password != '' || plaintxt != '') {
            cleanCriptoBtn.classList.remove('hidden');
        }else {
            cleanCriptoBtn.classList.add('hidden');
        }
    }
    document.querySelector('#textoPlano').oninput = function () {
        const password = document.querySelector('#claveCifrado').value;
        const plaintxt = document.querySelector('#textoPlano').value;
        if (password != '' || plaintxt != '') {
            cleanCriptoBtn.classList.remove('hidden');
        }else {
            cleanCriptoBtn.classList.add('hidden');
        }
    }
    cleanCriptoBtn.addEventListener('click', () => {
        cleanCriptoBtn.disabled = true;
        loaderCripto.classList.remove('hidden');
        document.querySelector('#claveCifrado').value = "";
        document.querySelector('#textoPlano').value = "";
        errorNBits.classList.add('hidden');
        errorPassword.classList.add('hidden');
        errorPlaintxt.classList.add('hidden');
        loaderCripto.classList.add('hidden');
        resetCriptoBtn.classList.add('hidden');
        respuestaCripto.classList.add('hidden');
        document.querySelector('#textoCifradoPlano').innerHTML = '';
        criptoBtn.disabled = false;
        criptoBtn.classList.remove('hidden');
        cleanCriptoBtn.disabled = false;
        cleanCriptoBtn.classList.add('hidden');
    });
    criptoBtn.addEventListener('click', () => {
        criptoBtn.disabled = true;
        loaderCripto.classList.remove('hidden');
        errorNBits.classList.add('hidden');
        errorPassword.classList.add('hidden');
        errorPlaintxt.classList.add('hidden');

        const nBits = parseInt(document.querySelector('input[name="sizeKeyCifrar"]:checked').value);
        const password = document.querySelector('#claveCifrado').value;
        const plaintxt = document.querySelector('#textoPlano').value;

        if (password == '') {errorPassword.classList.remove('hidden');}
        if (plaintxt == '') {errorPlaintxt.classList.remove('hidden');}
        if (nBits == '' || password == '' || plaintxt == ''){
            criptoBtn.disabled = false;
            loaderCripto.classList.add('hidden');
        }
        else {
            const t1 = performance.now();
            const encrtext = AesCtr.encrypt(plaintxt, password, nBits);
            const t2 = performance.now();
            document.querySelector('#textoCifradoPlano').innerHTML = encrtext;
            document.querySelector('#tiempoCifrado').innerHTML = (t2 - t1).toFixed(3) + 'ms';
            loaderCripto.classList.add('hidden');
            criptoBtn.classList.add('hidden');
            respuestaCripto.classList.remove('hidden');
            resetCriptoBtn.classList.remove('hidden');
        }
    });
    resetCriptoBtn.addEventListener('click', () => {
        resetCriptoBtn.disabled = true;
        loaderCripto.classList.remove('hidden');
        errorNBits.classList.add('hidden');
        errorPassword.classList.add('hidden');
        errorPlaintxt.classList.add('hidden');

        const nBits = parseInt(document.querySelector('input[name="sizeKeyCifrar"]:checked').value);
        const password = document.querySelector('#claveCifrado').value;
        const plaintxt = document.querySelector('#textoPlano').value;

        if (password == '') {
            errorPassword.classList.remove('hidden');
        }
        if (plaintxt == '') {
            errorPlaintxt.classList.remove('hidden');
        }
        if (nBits == '' || password == '' || plaintxt == '') {
            criptoBtn.disabled = false;
            loaderCripto.classList.add('hidden');
        }
        else {
            const t1 = performance.now();
            const encrtext = AesCtr.encrypt(plaintxt, password, nBits);
            const t2 = performance.now();
            document.querySelector('#textoCifradoPlano').innerHTML = encrtext;
            document.querySelector('#tiempoCifrado').innerHTML = (t2 - t1).toFixed(3) + 'ms';
            loaderCripto.classList.add('hidden');
            resetCriptoBtn.disabled = false;
            respuestaCripto.classList.remove('hidden');
            resetCriptoBtn.classList.remove('hidden');
        }
    });
    //Desencriptar
    document.querySelector('#claveDecifrado').oninput = function () {
        const password = document.querySelector('#claveDecifrado').value;
        const plaintxt = document.querySelector('#textoCifrado').value;
        if (password != '' || plaintxt != '') {
            cleanDescifrarBtn.classList.remove('hidden');
        } else {
            cleanDescifrarBtn.classList.add('hidden');
        }
    }
    document.querySelector('#textoCifrado').oninput = function () {
        const password = document.querySelector('#claveDecifrado').value;
        const plaintxt = document.querySelector('#textoCifrado').value;
        if (password != '' || plaintxt != '') {
            cleanDescifrarBtn.classList.remove('hidden');
        } else {
            cleanDescifrarBtn.classList.add('hidden');
        }
    }
    cleanDescifrarBtn.addEventListener('click', () => {
        cleanDescifrarBtn.disabled = true;
        loaderDescripto.classList.remove('hidden');
        document.querySelector('#claveDecifrado').value = "";
        document.querySelector('#textoCifrado').value = "";
        loaderDescripto.classList.add('hidden');
        respuestaDescripto.classList.add('hidden');
        errorNBitsDC.classList.add('hidden');
        errorPasswordDC.classList.add('hidden');
        errorPlaintxtDC.classList.add('hidden');
        document.querySelector('#textoDecifrado').innerHTML = '';
        decifrarBtn.disabled = false;
        decifrarBtn.classList.remove('hidden');
        cleanDescifrarBtn.disabled = false;
        cleanDescifrarBtn.classList.add('hidden');
    });
    decifrarBtn.addEventListener('click', () => {
        decifrarBtn.disabled = true;
        loaderDescripto.classList.remove('hidden');
        errorNBitsDC.classList.add('hidden');
        errorPasswordDC.classList.add('hidden');
        errorPlaintxtDC.classList.add('hidden');
        erroraDescripto.classList.add('hidden');
        decifrarBtn.classList.remove('hidden');
        respuestaDescripto.classList.add('hidden');

        const nBits = parseInt(document.querySelector('input[name="sizeKeyDecifrar"]:checked').value);
        const password = document.querySelector('#claveDecifrado').value;
        const plaintxt = document.querySelector('#textoCifrado').value;

        if (password == '') { errorPasswordDC.classList.remove('hidden'); }
        if (plaintxt == '') { errorPlaintxtDC.classList.remove('hidden'); }
        if (nBits == '' || password == '' || plaintxt == '') {
            decifrarBtn.disabled = false;
            loaderDescripto.classList.add('hidden');
        }
        else {
            const t1 = performance.now();
            try {
                const decrtext = AesCtr.decrypt(plaintxt, password, nBits);
                const t2 = performance.now();
                document.querySelector('#textoDecifrado').innerHTML = decrtext;
                document.querySelector('#tiempoDecifrado').innerHTML = (t2 - t1).toFixed(3) + 'ms';
                respuestaDescripto.classList.remove('hidden');
                //decifrarBtn.classList.add('hidden');
                //resetCriptoBtn.classList.remove('hidden');
            } catch (e) {
                const t2 = performance.now();
                respuestaDescripto.classList.add('hidden');
                document.querySelector('#textoDecifrado').value = '';
                document.querySelector('#error-tiempoDecifrado').innerHTML = (t2 - t1).toFixed(3) + 'ms';
                document.querySelector('#error-decrypt').innerHTML = 'Al parecer, los datos ingresados no son correctos.<br><span class="text-xs font-bold">Error:</span> <span class="text-xs">'+e.message+'</span>';
                erroraDescripto.classList.remove('hidden');
            }
            loaderDescripto.classList.add('hidden');
            decifrarBtn.disabled = false;
        }
    });
});