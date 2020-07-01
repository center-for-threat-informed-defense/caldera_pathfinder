var refresher
var latest_source
var current_report

function changeInputOptions(event, section) {
    $('.pathfinderSection').css('display', 'none');
    $('.tab-bar button').removeClass('selected');

    $('#'+section).toggle();
    event.currentTarget.className = "selected";
    if (section == 'graphSection') {
        $('#logView').css('display', 'none')
        $('#graphView').css('display', 'block')
    } else {
        $('#logView').css('display', 'block')
        $('#graphView').css('display', 'none')
    }
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
    validateFormState(false, '#viewFacts');
    let script = $()
    let target = $('#targetInput').val();
    displayOutput('scan started on target: ' + target);
    let data = {'index':'scan',
                'network':'local',
                'target':target,
                'script':$('#scanScriptSelection').val()
                };
    restRequest('POST', data, processResults, '/plugin/pathfinder/api');
}

function importScan(){
    $('#fileInput').trigger('click');
}

function processScan(filename){
    function processResults(data){
        if(data.status == 'pass'){
            displayOutput('report imported, new source created');
            displayOutput(data.output);
            openSource(data.source);
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
    restRequest('POST', data, processResults, '/plugin/pathfinder/api');
}

function restPostFile(file, callback=null, endpoint='/plugin/pathfinder/upload'){
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
    current_report = $('#vulnerabilityReport').val();
    loadGraph('graphView', '/plugin/pathfinder/graph?report='+current_report);
    stream('Right click to select starting and ending points to create an adversary');
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
    restRequest('POST', {'index':'reports'}, updateData, '/plugin/pathfinder/api');
}

function openSource(source_id){
    viewSection('sources', '/advanced/sources');
    setTimeout(function(s){ $('#profile-source-name').val(s).change(); }, 1000, source_id);
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
            latest_source = source_id;
            validateFormState(true, '#viewFacts');
            reloadReports();
        }
        if (number_failed > 0){
            for (var key in data.errors){
                displayOutput('scan of '+key+' failed. error output: '+data.errors[key].message);
            }
        }
    }
    restRequest('POST', {'index':'status'}, updateData, '/plugin/pathfinder/api');
}

function openFacts(){
    openSource(latest_source);
}

function loadGraph(element, address){
    function display(data) {
        let content = $($.parseHTML(data, keepScripts=true));
        let elem = $('#'+element);
        elem.html(content);
    }
    restRequest('GET', null, display, address);
}

function downloadVulnerabilityReport(){
    current_report = $('#vulnerabilityReport').val();
    stream('Downloading report: '+ current_report);
    uri = "/plugin/pathfinder/download?report_id=" + current_report;
    let downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", uri);
    downloadAnchorNode.setAttribute("download", current_report + ".yml");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}