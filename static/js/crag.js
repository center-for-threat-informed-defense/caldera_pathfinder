function toggleInputOptions() {
    $('#importSection').toggle();
    $('#scanSection').toggle();
}

function validateNmapInstalled(state){
    validateFormState(state, '#startScan');
}

function validateParser(){
    validateFormState(true, '#startImport');
}

function startScan(){
    function processResults(data){
        if(data.status == 'pass'){
            displayOutput('scan passed, found new facts');
            displayOutput(data.output);
        }else{
            displayOutput('scan failed, please check server logs for issue');
        }
        validateFormState(true, '#startScan');
    }
    validateFormState(false, '#startScan');
    let target = $('#targetInput').val();
    displayOutput('scan started on target: ' + target);
    restRequest('POST', {'index':'scan', 'network':'local', 'target':target}, processResults, '/plugin/crag/api');
}

function importScan(){
    $('#fileInput').trigger('click');
}

function processScan(filename){
    function processResults(data){
        if(data.status == 'pass'){
            displayOutput('report imported, new source created');
            displayOutput(data.output);
        }else{
            displayOutput('report import failed, please check server logs for issue');
        }
        validateFormState(true, '#startImport');
    }
    validateFormState(false, '#startImport');
    let data = {'index': 'import_scan',
                'format': $('#scanInputFormat').val(),
                'filename': filename
                }
    restRequest('POST', data, processResults, '/plugin/crag/api');
}

function restPostFile(file, callback=null, endpoint='/plugin/crag/upload'){
    let fd = new FormData();
    fd.append('file', file);
    $.ajax({
        type: 'POST',
        url: endpoint,
        data: fd,
        processData: false,
        contentType: false,
        success: function(data, status, options) {
            if(callback) {
                callback(data);
            }
            stream("successfully uploaded " + file.name);
        },
        error: function (xhr, ajaxOptions, thrownError) {
            stream(thrownError);
        }
    });
}

$('#fileInput').on('change', function (event){
    if(event.currentTarget) {
        let filename = event.currentTarget.files[0].name;
            if(filename){
                restPostFile(event.currentTarget.files[0], function (data) {processScan(filename);})
                event.currentTarget.value = '';

            }
    }
});


function displayOutput(text){
    document.getElementById("cragLog").value += text + '\n'
}