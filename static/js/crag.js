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
    restRequest('POST', {'index':'scan', 'network':'local'}, displayOutput, '/plugin/crag/api');
}

function importScan(){
    $('#fileInput').trigger('click');
}

function processScan(filename){
    let data = {'index': 'import_scan',
                'format': $('#scanInputFormat').val(),
                'filename': filename
                }
    restRequest('POST', data, displayOutput, '/plugin/crag/api');
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


function displayOutput(data){
    let results = data;
    document.getElementById("cragLog").value += results.output + '\n'
}