var data;
function setData(d){
    data = d;
    draw(data);
}
var created_adversary

var sourceNode, targetNode;
var width = $('#graphContainer').width();
var height = $(window).height() * 0.8; //$('#graphContainer').height(); the dynamic loading of the modals catches this in a transition state
var config = {
        linkDistance: 50,
        propertyScaleFactor: .2   //scale factor relative to node size
    };

var group_colors = {'scanners': 'grey', 'hosts': 'deepskyblue', 'cves':'orangered', 'ports':'blue'};
var node_radii = {'scanners': 15, 'hosts': 15, 'cves': 5, 'ports': 10};
var link_lengths = {'network': 2, 'port': 1, 'cve': 1, 'path': 4};
var link_colors = {'network': '#999', 'port': '#999', 'cve': '#999', 'path': '#ff0'};

var svg = d3.select('#networkGraph')
    .call(dynamicallyCenter)
    .append('g');

var simulation = d3.forceSimulation()
    .force('link', d3.forceLink())
    .force('charge', d3.forceManyBody())
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(function(d) {return node_radii[d.group]}));

var nodes;

var draw = function(graph) {

    svg.selectAll('g.links').remove();
    var link = svg.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(graph.links)
        .enter().append('line')
            .attr('stroke-width', 3)
            .attr('stroke', function(d) {return link_colors[d.type]});

    svg.selectAll('g.nodes').remove();
    nodes = svg.append('g')
        .attr('class', 'nodes')
        .selectAll('g')
        .data(graph.nodes)
        .enter().append('g')
            .attr('class', 'node')
            .call(d3.drag()
                .on('start', function dragstarted(d) {
                    if (!d3.event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                })
                .on('drag', function dragged(d) {
                    d.fx = d3.event.x;
                    d.fy = d3.event.y;
                })
                .on('end', function dragended(d) {
                    if (!d3.event.active) simulation.alphaTarget(0);
                }));

    nodes.append('circle')
        .attr('r', function(d) { return node_radii[d.group] })
        .attr('fill', function(d) { return group_colors[d.group];})
        .on('contextmenu', d3.contextmenu(menu))
        .on('dblclick', freeNode);

    nodes.append('title')
        .text(function(d) { return d.label; });

    nodes.append('text')
        .attr('dx', function(d) {return node_radii[d.group]/2 + 8})
        .attr('dy', ".35em")
        .attr("stroke", function(d) { if(d.dim) return "grey"; else return "white"; })
        .attr("fill", function(d) { if(d.dim) return "grey"; else return "white"; })
        .text(function(d) {return d.label})

    simulation
        .nodes(graph.nodes)
        .on('tick', function ticked() {
            link
                .attr('x1', function(d) { return d.source.x; })
                .attr('y1', function(d) { return d.source.y; })
                .attr('x2', function(d) { return d.target.x; })
                .attr('y2', function(d) { return d.target.y; });
            nodes.attr('transform', function(d) {return 'translate(' + d.x + ',' + d.y + ')';});
        })
        .force('link')
        .links(graph.links);
};

function addVisualizationLinks() {
}

function updateLinkDistance(linkDistance) {
    d3.select('#link-distance-value').text(linkDistance);
    d3.select('#link-distance').property('value', linkDistance);
}

simulation.force('link')
    .id(function(d) {return d.id;})
    .distance(function(d) {return config.linkDistance*link_lengths[d.type];});

d3.select('#link-distance').on('input', function() {
    config.linkDistance = +this.value;
    updateLinkDistance(config.linkDistance);
    simulation.force('link').distance(function(d) {return config.linkDistance*link_lengths[d.type];});
    simulation.alpha(1).restart();
});

updateLinkDistance(config.linkDistance);

function freeNode(d) {
    d.fx = null;
    d.fy = null;
}

function dynamicallyCenter(svg) {
    const container = d3.select(svg.node().parentNode);
    d3.select(window).on('resize.' + container.attr('id'), resize);

    function resize() {
        const targetWidth = parseInt(container.style('width'));
        const targetHeight = parseInt(container.style('height'));
        simulation.force('center', d3.forceCenter(targetWidth / 2, targetHeight / 2));
    }
}

function updateElements(){
    nodes.selectAll('g circle')
        .attr('fill', function(d){
            if(d.id == sourceNode){
                return '#0f0';
            }
            else if(d.id == targetNode){
                return '#f00';
            }
            else {
                return group_colors[d.group];
            }
        });
    if(sourceNode && targetNode){
        validateFormState(true, '#createAdversary');
    }
}

function clearSelections(){
    sourceNode = null;
    targetNode = null;
}

// Context Menu
var menu = [
    {
        label: 'set source node',
        action: function(d, index) {
            if(d.group == 'hosts'){
                sourceNode = d.id;
                updateElements();
            }
        }
    },
    {
        label: 'set target node',
        action: function(d, index) {
            if(d.group == 'hosts'){
                targetNode = d.id;
                updateElements();
            }
        }
    },
    {
        label: 'info',
        items:[
        {
            label: function(d, index) { return d.id; },
            action: function(d, index) {}
        }
        ]
    }
];

function createAdversary(){
    report = $('#vulnerabilityReport').val();
    tags = $('#adversaryTags').val();
    let data = {
        'index': 'create_adversary',
        'id': report,
        'start': sourceNode,
        'target': targetNode,
        'adversary_tags': tags
    }
    apiV2('POST', '/plugin/pathfinder/api', data).then((response) => {
        removeOldPaths();
        addNewLinks(response.new_links);
        created_adversary = response.adversary_id;
        validateFormState(true, '#viewAdversaries');
        validateFormState(true, '#setupOperation');
        toast('Custom Pathfinder adversary created.', true);
    }).catch((error) => {
        toast('Error creating adversary, please ensure target node has a tagged CVE.', false);
        console.error(error);
    });
}

function openAdversary(adversary_id){
    viewSection('profiles', '/campaign/profiles');
    setTimeout(function(s){ $('#profile-existing-name').val(s).change(); }, 1000, adversary_id);
}

function addNewLinks(links){
    for (var link in links) {
        data.links.push(links[link]);
    }
    draw(data);
    updateElements();
    simulation.alpha(1).restart();
}

function removeOldPaths() {
    for(var link in data.links) {
        if(data.links[link].type == 'path') {
            data.links.pop(link);
        }
    }
    draw(data);
    updateElements();
    simulation.alpha(1).restart();
}

