function toast(mensaje) {
    const Toast = Swal.mixin({
        toast: true,
        position: 'top-end',
        showConfirmButton: false,
        timer: 3000,
        timerProgressBar: true,
        didOpen: (toast) => {
            toast.addEventListener('mouseenter', Swal.stopTimer)
            toast.addEventListener('mouseleave', Swal.resumeTimer)
        }
    })

    Toast.fire({
        icon: 'success',
        title: mensaje
    })
}
function copyToClipBoard() {
    var content = document.getElementById('textoCifradoPlano').innerHTML;
    navigator.clipboard.writeText(content).then(() => {
        toast("Texto copiado en el portapapeles.")
    }).catch(err => {
        toast('Algo salió mal, ', err);
    })
}