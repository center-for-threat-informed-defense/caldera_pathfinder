var data;
function setData(d){
    data = d;
}

var width = $('#graphContainer').width();
var height = $(window).height() * 0.8; //$('#graphContainer').height(); the dynamic loading of the modals catches this in a transition state

var svg = d3.select('#networkGraph')
    .call(dynamicallyCenter)
    .append('g')

var simulation = d3.forceSimulation()
    .force('link', d3.forceLink())
    .force('charge', d3.forceManyBody())
    .force('center', d3.forceCenter(width / 2, height / 2));

var group_colors = {1: 'grey', 2: 'deepskyblue', 3:'orangered'};

// eventually use different symbols for ports with exploits vs open ports vs protected ports
var propertySymbolFiles = [
    '/crag/img/item-bell.svg',
    '/crag/img/item-bolt.svg',
    '/crag/img/item-certificate.svg',
    '/crag/img/item-exclamation.svg'];

var propertySymbolSVGs = [],
    degreeToRadians = Math.PI / 180,
    nodes,
    config = {
        linkDistance:350,
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
            .attr('stroke-width', function(d) { return Math.sqrt(d.value); });

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
    nodes.append('title')
        .text(function(d) { return d.id; });

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

    //change this to be equidistant around the node, or co-aligned with the link that relates to a CVE on the port
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
    .distance(function(d) {return config.linkDistance/d.value;});

d3.select('#link-distance').on('input', function() {
    config.linkDistance = +this.value;
    updateLinkDistance(config.linkDistance);
    simulation.force('link').distance(function(d) {return config.linkDistance/d.value;});
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