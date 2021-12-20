var refresher
var latest_source
var current_report
var scanner_fields = []


function changeInputOptions(event, section) {
    $('.pathfinderSection').css('display', 'none');
    $('.tab-bar button').removeClass('selected');
    $('#'+section).toggle();
    event.currentTarget.className = "selected";
    if (section == 'graphSection') {
        $('#logView').css('display', 'none')
        $('#graphView').css('display', 'block')
        reloadReports();
    } else {
        $('#logView').css('display', 'block')
        $('#graphView').css('display', 'none')
    }
}

function validateParser(){
    validateFormState(true, '#startImport');
}

function startScan(){
    function processResults(data){
        if(data.status == 'pass'){
            displayOutput(data.output);
            refresher = setInterval(checkScanStatus, 10000);
        }else if(data.status == 'fail'){
            displayOutput('scan issue, ' + data.output + ' please check server logs for more details');
            validateFormState(true, '#startScan')
        }
    }
    validateFormState(false, '#startScan');
    validateFormState(false, '#viewFacts');
    scanner = $('#scannerSelection').val();
    let fields = {};
    for (var param in scanner_fields){
        fields[scanner_fields[param]] = $('#'+scanner_fields[param]).val();
    }
    displayOutput(scanner + ' scan started with parameters:\n' + JSON.stringify(fields, null, 4));
    let data = {'index':'scan',
                'scanner': scanner,
                'fields':fields
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
            latest_source = data.source;
            openSource(data.source);
            reloadReports();
        }else{
            displayOutput('report import failed, please check server logs for issue');
        }
        validateFormState(true, '#startImport');
    }
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
                displayOutput('scan ID:'+key+' finished. new source created: '+data.finished[key].source);
                source_id = data.finished[key].source_id;
            }
            latest_source = source_id;
            validateFormState(true, '#viewFacts');
            reloadReports();
        }
        if (number_failed > 0){
            for (var key in data.errors){
                displayOutput('scan ID:'+key+' failed. error output: '+data.errors[key].message);
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

function renameVulnerabilityReport(){
    current_report = $('#vulnerabilityReport').val();
    let new_name = $('#newReportName').val();
    stream('Renaming report: ' + current_report + ' to ' + new_name);
    apiV2('PATCH', '/plugin/pathfinder/api', {'index':'report','id':current_report, 'rename':new_name});
    $('#vulnerabilityReport').empty();
    reloadReports();
}

function downloadVulnerabilityReport(){
    current_report = $('#vulnerabilityReport').val();
    current_report_name = $('#vulnerabilityReport option:selected').text()
    stream('Downloading report: ' + current_report_name);
    uri = "/plugin/pathfinder/download?report_id=" + current_report;
    let downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", uri);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}

function removeVulnerabilityReport(){
    current_report = $('#vulnerabilityReport').val();
    stream('Removing report: '+ current_report);
    apiV2('DELETE', '/plugin/pathfinder/api', {'index':'report','id':current_report});
    $('#vulnerabilityReport').empty();
    reloadReports();
}

function setupScannerSection(){
    function setupScanner(data) {
        $('#dynamicScannerSection').empty();
        validateFormState(data.enabled, '#startScan');
        if(data.error){
            displayOutput(data.name + ': ' + data.error);
            return;
        }
        if(!data.enabled) {
            displayOutput(data.name + ': Please install scanner dependencies before scanning, scanning disabled!');
            return;
        }
        while(scanner_fields.length > 0) { scanner_fields.pop(); }
        for (var field in data.fields) {
            addScannerField($('#scannerSelection').val(), data.fields[field].type, data.fields[field]);
        }

    }
    selected_scanner = $('#scannerSelection').val();
    restRequest('POST', {'index':'scanner_config', 'name':selected_scanner}, setupScanner, '/plugin/pathfinder/api');
}

function addScannerField(scanner, type, field_data) {
    function setupTextField(config) {
        let template = $('#textInputTemplate').clone();
        template.attr('id', scanner + config.param);
        template.find('label').text(config.name);
        template.find('input').attr('id', config.param);
        if (config.default != null)
            template.find('input').attr('value', config.default);
        template.show();
        $('#dynamicScannerSection').append(template);
    }
    function setupPulldownField(config) {
        let template = $('#pulldownInputTemplate').clone();
        template.attr('id', scanner + config.param);
        template.find('label').text(config.name);
        let selection = template.find('select');
        selection.attr('id', config.param);
        if (config.prompt != null)
            selection.append($('<option value="" disabled selected>' + config.prompt + '</option>'));
        config.values.forEach(function(script) {selection.append($('<option value="' + script + '">' + script + '</option>'));})
        template.show();
        $('#dynamicScannerSection').append(template);
    }
    function setupCheckboxField(config) {
        let template = $('#checkboxInputTemplate').clone();
        template.attr('id', scanner + config.param);
        template.find('input').attr('id', config.param);
        template.find('span').text(config.name);
        template.show();
        $('#dynamicScannerSection').append(template);
    }

    var setupFunctions = {'text': setupTextField,
                          'pulldown': setupPulldownField,
                          'checkbox': setupCheckboxField
                          };
    setupFunctions[type](field_data);
    scanner_fields.push(field_data.param);
}
