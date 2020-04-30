function toggleInputOptions() {
    $('#scan-input-format').toggle();
    $('#start-import').toggle();
    $('#start-scan').toggle();
}

function validateNmapInstalled(state){
    validateFormState(state, '#startScan');
}

function validateParser(){
    validateFormState(true, '#startImport')
}

function startScan(){
}

function importScan(){
}
