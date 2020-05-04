function toggleInputOptions() {
    $('#scan-input-format').toggle();
    $('#start-import').toggle();
    $('#start-scan').toggle();
}

function validateNmapInstalled(state){
    validateFormState(state, '#startScan');
}

function validateParser(){
    validateFormState(true, '#startImport');
}

function startScan(){
    restRequest('POST', {'index':'scan', 'network':'local'}, displayOutput, '/plugin/crag/api');
}

function importScan(){
    $('#file-input').trigger('click');
}

function uploadScan(file){
//    let file = $('#file-input').files[0];
//    let file = document.getElementById('file-input').files[0];
    let data = {'index': 'import_scan',
                'format': $('#scan-input-format').val(),
                'file': file
                }
    restRequest('POST', data, displayOutput, '/plugin/crag/api');
}

$('#file-input').on('change', function (event){
        if(event.currentTarget) {
            let filename = event.currentTarget.files[0].name;
            if(filename){
                uploadScan(event.currentTarget.files[0]);
            }
        }
    });


function displayOutput(data){
    let results = data;
    document.getElementById("crag-log").value += results.output + '\n'
}