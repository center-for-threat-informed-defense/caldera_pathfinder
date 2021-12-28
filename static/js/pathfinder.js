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
    apiV2('POST', '/plugin/pathfinder/api', data).then((response) => {
        displayOutput(response.output);
        refresher = setInterval(checkScanStatus, 10000);
    }).catch((error) => {
        validateFormState(true, '#startScan')
        toast('scan issue, please check server logs for more details', false);
        console.error(error);
    });
}

function importScan(){
    $('#fileInput').trigger('click');
}

function processScan(filename){
    let data = {'index': 'import_scan',
                'format': $('#scanInputFormat').val(),
                'filename': filename
                }
    apiV2('POST', '/plugin/pathfinder/api', data).then((response) => {
        displayOutput('report imported, new source created');
        displayOutput(response.output);
        latest_source = response.source;
        reloadReports();
        toast('Report created, view it in the "View" tab.', true);
    }).catch((error) => {
        displayOutput('report import failed, please check server logs for issue');
        toast('Error importing report, please verify it matches the selected parser.', false);
        console.error(error);
    });
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
    apiV2('POST', '/plugin/pathfinder/api', {'index':'reports'}).then((response) => {
        response.reports.forEach(function(r) {
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
    }).catch((error) => {
        toast('Error reloading Pathfinder reports.', false);
        console.error(error);
    });
}

function checkScanStatus(){
    apiV2('POST', '/plugin/pathfinder/api', {'index':'status'}).then((response) => {
        number_finished = Object.keys(response.finished).length
        number_failed = Object.keys(response.errors).length
        if (response.pending.length == 0){
            validateFormState(true, '#startScan');
            if(number_finished == 0 && number_failed == 0){
                clearInterval(refresher);
            }
        }
        if (number_finished > 0){
            source_id = '';
            for (var key in response.finished){
                displayOutput(`scan ID:${key} finished. new source created: ${response.finished[key].source}`);
                source_id = response.finished[key].source_id;
            }
            latest_source = source_id;
            validateFormState(true, '#viewFacts');
            reloadReports();
        }
        if (number_failed > 0){
            for (var key in response.errors){
                displayOutput('scan ID:'+key+' failed. error output: '+response.errors[key].message);
            }
        }
    }).catch((error) => {
        toast('Error creating adversary, please ensure target node has a tagged CVE.', false);
        console.error(error);
    });
}

function loadGraph(element, address){
    apiV2('GET', address, null).then((response) => {
        let content = $($.parseHTML(response, keepScripts=true));
        let elem = $('#'+element);
        elem.html(content);
    }).catch((error) => {
        toast('Error loading attack graph.', false);
        console.error(error);
    });
}

function renameVulnerabilityReport(){
    current_report = $('#vulnerabilityReport').val();
    let new_name = $('#newReportName').val();
    stream('Renaming report: ' + current_report + ' to ' + new_name);
    apiV2('PATCH', '/plugin/pathfinder/api', {'index':'report', 'id':current_report, 'rename':new_name});
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
    selected_scanner = $('#scannerSelection').val();
    apiV2('POST', '/plugin/pathfinder/api', {'index':'scanner_config', 'name':selected_scanner}).then((response) => {
        $('#dynamicScannerSection').empty();
        validateFormState(response.enabled, '#startScan');
        if(response.error){
            displayOutput(response.name + ': ' + response.error);
            return;
        }
        if(!response.enabled) {
            displayOutput(response.name + ': Please install scanner dependencies before scanning, scanning disabled!');
            return;
        }
        while(scanner_fields.length > 0) { scanner_fields.pop(); }
        for (var field in response.fields) {
            addScannerField($('#scannerSelection').val(), response.fields[field].type, response.fields[field]);
        }
    }).catch((error) => {
        toast('Error setting up scanner.', false);
        console.error(error);
    });
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
