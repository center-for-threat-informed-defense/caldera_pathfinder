var refresher

function changeInputOptions(event, section) {
    $('.cragSection').css('display', 'none');
    $('.tab-bar button').removeClass('selected');

    $('#'+section).toggle();
    event.currentTarget.className = "selected";
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
            displayOutput(data.output);
            refresher = setInterval(checkScanStatus, 20000);
        }else{
            displayOutput('scan issue, ' + data.output + ' please check server logs for more details');
        }
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
            viewSection('sources', '/advanced/sources');
            setTimeout(function(s){ $('#profile-source-name').val(s).change(); }, 1000, data.source);
            reloadReports();
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
    document.getElementById("logWindow").value += text + '\n'
}

function graphReport() {
    report = $('#vulnerabilityReport').val();
    viewSection('craggraph', '/plugin/crag/graph?report='+report);
}

function reloadReports(){
    function updateData(data){
        data.reports.forEach(function(r) {
            let found = false;
            $("#vulnerabilityReport > option").each(function() {
                if($(this).val() === r.id) {
                    found = true;
                }
            });
            if(!found){
                $('#vulnerabilityReport').append('<option value="'+r.id+'">'+r.name+'</option>');
            }
        });
    }
    restRequest('POST', {'index':'reports'}, updateData, '/plugin/crag/api');
}

function checkScanStatus(){
    function updateData(data){
        number_finished = Object.keys(data.finished).length
        number_failed = Object.keys(data.errors).length
        if (data.pending.length == 0){
            validateFormState(true, '#startScan');
            if(number_finished == 0 && number_failed == 0){
                clearInterval(refresher);
            }
        }
        if (number_finished > 0){
            source_id = '';
            for (var key in data.finished){
                displayOutput('scan of '+key+' finished. new source created: '+data.finished[key].source);
                source_id = data.finished[key].source_id;
            }
            viewSection('sources', '/advanced/sources');
            setTimeout(function(s){ $('#profile-source-name').val(s).change(); }, 1000, source_id);
            reloadReports();
        }
        if (number_failed > 0){
            for (var key in data.errors){
                displayOutput('scan of '+key+' failed. error output: '+data.errors[key].message);
            }
        }
    }
    restRequest('POST', {'index':'status'}, updateData, '/plugin/crag/api');
}
