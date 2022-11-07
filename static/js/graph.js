// Global Variables
const group_colors = { 'scanners': 'grey', 'hosts': 'deepskyblue', 'cves':'orangered', 'ports':'blue' };
const node_radii = { 'scanners': 15, 'hosts': 15, 'cves': 5, 'ports': 10 };
const link_lengths = { 'network': 2, 'port': 1, 'cve': 1, 'path': 4 };
const link_colors = { 'network': '#999', 'port': '#999', 'cve': '#999', 'path': '#ff0' };
const contextMenu = [
    {
        label: 'Set source node',
        action: (d, index) => {
            if (d.group == 'hosts') {
                sourceNode === d.id ? sourceNode = null : sourceNode = d.id;
                updateElements();
            }
        }
    },
    {
        label: 'Set target node',
        action: (d, index) => {
            if (d.group == 'hosts') {
                targetNode === d.id ? targetNode = null : targetNode = d.id;
                updateElements();
            }
        }
    },
    {
        label: 'Info',
        items: [
            {
                label: (d, index) => d.id,
                action: (d, index) => {}
            }
        ]
    }
];

let graphData;
let svg;
let nodes;
let simulation;
let width;
let height;
let config = { linkDistance: 50, propertyScaleFactor: 0.2 };
let sourceNode, targetNode;

function initGraph(data, linkDistance) {
    graphData = JSON.parse(JSON.stringify(data));
    d3.selectAll('g').html(null);
    
    // Set dimensions
    width = document.getElementById('graphContainer').offsetWidth;
    height = window.innerHeight * 0.8;
    config.linkDistance = linkDistance;

    // Setup simulation
    simulation = d3.forceSimulation()
        .force('link', d3.forceLink())
        .force('charge', d3.forceManyBody())
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius((d) => node_radii[d.group]));
    simulation.force('link')
        .id((d) => d.id)
        .distance((d) => config.linkDistance * link_lengths[d.type]);

    svg = d3.select('#networkGraph')
        .call(dynamicallyCenter)
        .append('g');
    
    draw();
}

function dynamicallyCenter(svg) {
    const container = d3.select(svg.node().parentNode);
    d3.select(window).on(`resize.${container.attr('id')}`, () => {
        const targetWidth = parseInt(container.style('width'));
        const targetHeight = parseInt(container.style('height'));
        simulation.force('center', d3.forceCenter(targetWidth / 2, targetHeight / 2));
    });
}

function draw() {
    svg.selectAll('g.links').remove();
    var link = svg.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(graphData.links)
        .enter().append('line')
            .attr('stroke-width', 3)
            .attr('stroke', (d) => link_colors[d.type]);

    svg.selectAll('g.nodes').remove();
    nodes = svg.append('g')
        .attr('class', 'nodes')
        .selectAll('g')
        .data(graphData.nodes)
        .enter().append('g')
            .attr('class', 'node')
            .call(d3.drag()
                .on('start', (d) => {
                    if (!d3.event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                })
                .on('drag', (d) => {
                    d.fx = d3.event.x;
                    d.fy = d3.event.y;
                })
                .on('end', (d) => {
                    if (!d3.event.active) simulation.alphaTarget(0);
                }));

    nodes
        .append('circle')
        .attr('r', (d) => node_radii[d.group])
        .attr('fill', (d) => group_colors[d.group])
        .on('contextmenu', d3.contextmenu(contextMenu))
        .on('dblclick', (d) => {
            d.fx = null;
            d.fy = null;
        });

    nodes
        .append('title')
        .text((d) => d.label);

    nodes
        .append('text')
        .attr('dx', (d) => node_radii[d.group] / 2 + 8)
        .attr('dy', ".35em")
        .attr("stroke", (d)  => (d.dim) ? "grey" : "white")
        .attr("fill", (d) => (d.dim) ? "grey" : "white")
        .text((d) => d.label)

    simulation
        .nodes(graphData.nodes)
        .on('tick', () => {
            link
                .attr('x1', (d) => d.source.x)
                .attr('y1', (d) => d.source.y)
                .attr('x2', (d) => d.target.x)
                .attr('y2', (d) => d.target.y);
            nodes.attr('transform', (d) => `translate(${d.x}, ${d.y})`);
        })
        .force('link')
        .links(graphData.links);
};

function updateLinkDistance(linkDistance = 50) {
    config.linkDistance = linkDistance;
    simulation.force('link').distance((d) => config.linkDistance * link_lengths[d.type]);
    simulation.alpha(1).restart();
}

function updateElements() {
    let createAdversaryBtn = document.getElementById('pathfinderCreateAdversary');
    if (sourceNode && targetNode) {
        createAdversaryBtn.removeAttribute('disabled');
    } else {
        createAdversaryBtn.setAttribute('disabled', true);
    }

    nodes
        .selectAll('g circle')
        .attr('fill', (d) => {
            if (d.id === sourceNode) return '#0f0';
            if (d.id === targetNode) return '#f00';
            return group_colors[d.group];
        });
}

function clearSelections() {
    sourceNode = null;
    targetNode = null;
}

async function createAdversary() {
    if (!sourceNode || !targetNode) return;
    try {
        const response = await apiV2('POST', '/plugin/pathfinder/api', {
            index: 'create_adversary',
            id: document.getElementById('reportId').value,
            start: sourceNode,
            target: targetNode,
            adversary_tags: document.getElementById('adversaryTags').value
        });
        removeOldPaths();
        addNewLinks(response.new_links);
        toast('Custom Pathfinder adversary created.', true);
    } catch(error) {
        console.error("Error creating adversary", error);
    }
}

function addNewLinks(links) {
   links.forEach((link) => graphData.links.push(link));
   draw();
   updateElements();
   simulation.alpha(1).restart(); 
}

function removeOldPaths() {
    graphData.links = graphData.links.filter((link) => link.type !== 'path');
    draw();
    updateElements();
    simulation.alpha(1).restart();
}
