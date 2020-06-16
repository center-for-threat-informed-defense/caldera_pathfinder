var data;
function setData(d){
    data = d;
}
var startingNode, targetNode;

var width = $('#graphContainer').width();
var height = $(window).height() * 0.8; //$('#graphContainer').height(); the dynamic loading of the modals catches this in a transition state

var svg = d3.select('#networkGraph')
    .call(dynamicallyCenter)
    .append('g')

var simulation = d3.forceSimulation()
    .force('link', d3.forceLink())
    .force('charge', d3.forceManyBody())
    .force('center', d3.forceCenter(width / 2, height / 2));

var group_colors = {'scanners': 'grey', 'hosts': 'deepskyblue', 'cves':'orangered'};

var propertySymbolFiles = [
    '/pathfinder/img/item-bell.svg',
    '/pathfinder/img/item-bolt.svg',
    '/pathfinder/img/item-certificate.svg',
    '/pathfinder/img/item-exclamation.svg'];

var propertySymbolSVGs = [],
    degreeToRadians = Math.PI / 180,
    nodes,
    config = {
        linkDistance:200,
        propertyScaleFactor : .2,   //scale factor relative to node size
        radius : 3,
        angleInitial : -45,
        angleIncrement : 45
    };

var draw = function(graph) {

    var link = svg.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(graph.links)
        .enter().append('line')
            .attr('stroke-width', 3);

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
                    d.fx = null;
                    d.fy = null;
                }));

    nodes.append('circle')
        .attr('r', function(d) {
                    if (d.ports) {
                        return 15+2*d.ports.length;
                    } else {
                        return 15;
                    }})
        .attr('fill', function(d) { return group_colors[d.group];})
        .on('contextmenu', d3.contextmenu(menu));

    nodes.append('title')
        .text(function(d) { return d.id; });

    nodes.append('text')
        .attr('dx', 12)
        .attr('dy', ".35em")
        .text(function(d) {return d.id})
      .clone(true).lower()
        .attr("fill", "none")
        .attr("stroke", "white")
        .attr("stroke-width", 3);

    var qualifiers = nodes
            .selectAll('.qualifier')
            .data(function(d) { return d.qualifiers; })
            .enter().append('g')
            .attr('class', 'qualifier');

    qualifiers.each(function(qualifier) {
        d3.select(this).node().appendChild(qualifier.cloneNode(true));
    });

    update(qualifiers);

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

var update = function(qualifier) {
    var item_radius,
        qualifier_size;

    qualifier.attr('transform', function(d, i) {
        item_radius = +d3.select(this.parentElement).select('circle').attr('r');
        return 'translate(' +
            item_radius * Math.cos((config.angleInitial + (config.angleIncrement * i)) * degreeToRadians) + ',' +
            item_radius * Math.sin((config.angleInitial + (config.angleIncrement * i)) * degreeToRadians) + ')';
        });
    qualifier.selectAll('g')
        .attr('transform', function(d, i) {
            item_radius = +d3.select(this.parentElement.parentElement).select('circle').attr('r');
            qualifier_size = (item_radius*2) * config.propertyScaleFactor;
            return 'scale(' + (qualifier_size / this.getBBox().width) + ')';
        });
}

function updateLinkDistance(linkDistance) {
    d3.select('#link-distance-value').text(linkDistance);
    d3.select('#link-distance').property('value', linkDistance);
}

simulation.force('link')
    .id(function(d) {return d.id;})
    .distance(function(d) {return config.linkDistance/Math.sqrt(d.value);});

d3.select('#link-distance').on('input', function() {
    config.linkDistance = +this.value;
    updateLinkDistance(config.linkDistance);
    simulation.force('link').distance(function(d) {return config.linkDistance/Math.sqrt(d.value);});
    simulation.alpha(1).restart();
});

updateLinkDistance(config.linkDistance);

var q = d3.queue();

propertySymbolFiles.forEach(function(propertySymbolFile) {
    q.defer(d3.xml, propertySymbolFile);
});

q.awaitAll(function(error, files) {
    if (error) throw error;
    files.forEach(function(file) {
        // assuming that every svg file contains a single child, a 'g'
        // node containing the visuals, get this placeholder
        propertySymbolSVGs.push(file.getElementsByTagName('svg')[0].getElementsByTagName('g')[0]);
    });

    //load network and add a set of qualifiers for each node.
    // each qualifier is a visual symbol
    graph = data;
    graph.nodes.forEach(function(node) {
        if (node.ports) {
            var ports = node.ports.length;
            node.qualifiers = [];
            for(var i=0; i<ports; i++)
                node.qualifiers.push(propertySymbolSVGs[2]);
        } else {
            node.qualifiers = [];
        }
    });
    draw(graph);
});

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
            if(d.id == startingNode){
                return '#0f0';
            }
            else if(d.id == targetNode){
                return '#f00';
            }
            else {
                return group_colors[d.group];
            }
        });
    if(startingNode && targetNode){
        validateFormState(true, '#createAdversary');
    }
}

function clearSelections(){
    startingNode = null;
    targetNode = null;
}

// Context Menu
var menu = [
    {
        label: 'task',
        items: [
        {
            label: 'set starting point',
            action: function(d, index) {
                if(d.group == 'hosts'){
                    startingNode = d.id;
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
        }
        ]
    },
    {
        label: 'info',
        action: function(d, index) {
            console.log(d);
            console.log(startingNode);
            console.log(targetNode);
        }
    }
];

function createAdversary(){
    function processResults(data){
        openAdversary(data.adversary_id);
        drawPath(data.new_links);
    }
    report = $('#vulnerabilityReport').val();
    let data = {
        'index': 'create_adversary',
        'id': report,
        'start': startingNode,
        'target': targetNode
    }
    restRequest('POST', data, processResults, '/plugin/pathfinder/api');
}

function openAdversary(adversary_id){
    viewSection('adversaries', '/section/profiles');
    setTimeout(function(s){ $('#profile-existing-name').val(s).change(); }, 1000, 'adversary-'+adversary_id);
}

function drawPath(links){

}
