// https://github.com/atago0129/d3-v4-contextmenu version 1.2.0 Atsushi Tago
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('d3')) :
  typeof define === 'function' && define.amd ? define(['exports', 'd3'], factory) :
  (factory((global.d3 = global.d3 || {}),global.d3));
}(this, (function (exports,d3) { 'use strict';

  var classCallCheck = function (instance, Constructor) {
    if (!(instance instanceof Constructor)) {
      throw new TypeError("Cannot call a class as a function");
    }
  };

  var createClass = function () {
    function defineProperties(target, props) {
      for (var i = 0; i < props.length; i++) {
        var descriptor = props[i];
        descriptor.enumerable = descriptor.enumerable || false;
        descriptor.configurable = true;
        if ("value" in descriptor) descriptor.writable = true;
        Object.defineProperty(target, descriptor.key, descriptor);
      }
    }

    return function (Constructor, protoProps, staticProps) {
      if (protoProps) defineProperties(Constructor.prototype, protoProps);
      if (staticProps) defineProperties(Constructor, staticProps);
      return Constructor;
    };
  }();

  var ContextMenuGroup = function () {

    /**
     * @param {string} id
     * @param {string|null} parentItemId
     * @param {number} nestedIndex
     */


    /** {string} */
    function ContextMenuGroup(id, parentItemId, nestedIndex) {
      classCallCheck(this, ContextMenuGroup);

      this.id = id;
      this.parentItemId = parentItemId;
      this.nestedIndex = nestedIndex;
    }

    /**
     * @param {ContextMenuItem} item
     * @returns {boolean}
     */


    /** {number} */


    /** {string} */


    createClass(ContextMenuGroup, [{
      key: "match",
      value: function match(item) {
        return item.groupId === this.id;
      }
    }]);
    return ContextMenuGroup;
  }();

  var ContextMenuItem = function () {

    /**
     * @param {string} id
     * @param {string} groupId
     * @param {string|function} label
     * @param {function} action
     */
    function ContextMenuItem(id, groupId, label, action) {
      classCallCheck(this, ContextMenuItem);
      this.defaultFill = 'rgb(250, 250, 250)';
      this.onMouseoverFill = 'rgb(200, 200, 200)';

      this.id = id;
      this.groupId = groupId;
      this.label = label;
      this.action = action;
    }

    /**
     * @param {*} d
     * @param {number} i
     * @param {HTMLElement} elm
     * @returns {string}
     */


    createClass(ContextMenuItem, [{
      key: 'getLabel',
      value: function getLabel(d, i, elm) {
        try {
          return String(this.label.bind(elm, d, i)());
        } catch (e) {
          return String(this.label);
        }
      }

      /**
       * @param {*} d
       * @param {number} i
       * @param {HTMLElement} elm
       */

    }, {
      key: 'onClick',
      value: function onClick(d, i, elm) {
        if (this.action !== null) {
          this.action.bind(elm, d, i)();
        }
      }
    }]);
    return ContextMenuItem;
  }();

  var ContextMenu = function () {

    /**
     * @param {*} d
     * @param {number} i
     * @param {HTMLElement} elm
     */


    /** {ContextMenuGroup[]} */


    /** {number} */
    function ContextMenu(d, i, elm) {
      classCallCheck(this, ContextMenu);
      this._groups = [];
      this._items = [];

      this.d = d;
      this.i = i;
      this.elm = elm;
    }

    /**
     * @param {ContextMenuGroup} group
     */


    /** {ContextMenuItem[]} */


    /** {HTMLElement} */

    /** {*} */


    createClass(ContextMenu, [{
      key: "pushGroup",
      value: function pushGroup(group) {
        this._groups.push(group);
      }

      /**
       * @param {ContextMenuItem} item
       */

    }, {
      key: "pushItem",
      value: function pushItem(item) {
        this._items.push(item);
      }

      /**
       * @returns {ContextMenuGroup}
       */

    }, {
      key: "getRootGroup",
      value: function getRootGroup() {
        return this.getGroupsByNestedIndex(0).pop();
      }

      /**
       * @param {string} id
       * @returns {ContextMenuGroup}
       */

    }, {
      key: "getGroupById",
      value: function getGroupById(id) {
        return this._groups.filter(function (group) {
          return group.id === id;
        }).pop() || null;
      }

      /**
       * @param {ContextMenuItem} item
       * @returns {ContextMenuGroup}
       */

    }, {
      key: "getGroupByParentItem",
      value: function getGroupByParentItem(item) {
        return this._groups.filter(function (group) {
          return group.parentItemId === item.id;
        }).pop() || null;
      }

      /**
       * @param {number} index
       * @returns {ContextMenuGroup[]}
       */

    }, {
      key: "getGroupsByNestedIndex",
      value: function getGroupsByNestedIndex(index) {
        return this._groups.filter(function (group) {
          return group.nestedIndex === index;
        });
      }

      /**
       * @param {ContextMenuGroup} group
       * @returns {ContextMenuItem[]}
       */

    }, {
      key: "getItemsByGroup",
      value: function getItemsByGroup(group) {
        return this._items.filter(function (item) {
          return group.match(item);
        });
      }
    }]);
    return ContextMenu;
  }();

  var ContextMenuFactory = function () {
    function ContextMenuFactory() {
      classCallCheck(this, ContextMenuFactory);
      this.itemIdIndex = 0;
      this.groupIdIndex = 0;
    }

    createClass(ContextMenuFactory, [{
      key: "factory",


      /**
       * @param {*} d
       * @param {number} i
       * @param {HTMLElement} elm
       * @param {object[]} dataSets
       * @returns {ContextMenu}
       */
      value: function factory(dataSets, d, i, elm) {
        this.contextMenu = new ContextMenu(d, i, elm);
        this.parseList(null, dataSets, 0);
        return this.contextMenu;
      }

      /**
       * @param {null|string} parentItemId
       * @param {object[]|function} dataSetList
       * @param {number} nestedIndex
       * @returns {ContextMenuGroup}
       */

    }, {
      key: "parseList",
      value: function parseList(parentItemId, dataSetList, nestedIndex) {
        var _this = this;

        this.groupIdIndex++;
        var groupId = 'd3_v4_context_menu_group_' + this.groupIdIndex;

        try {
          dataSetList = dataSetList();
        } catch (e) {}

        this.contextMenu.pushGroup(new ContextMenuGroup(groupId, parentItemId, nestedIndex));

        dataSetList.map(function (dataSet) {
          _this.itemIdIndex++;
          var itemId = 'd3_v4_context_menu_item_' + _this.itemIdIndex;
          var label = ContextMenuFactory.getLabel(dataSet);
          var action = ContextMenuFactory.getAction(dataSet);
          var children = ContextMenuFactory.getItems(dataSet);
          if (label === null || action === null && children === null) {
            throw new Error('Error!! ' + JSON.stringify(dataSet) + ' can not parse.');
          }
          _this.contextMenu.pushItem(new ContextMenuItem(itemId, groupId, label, action !== null ? action : null));
          if (children !== null) {
            _this.parseList(itemId, children, nestedIndex + 1);
          }
        });
      }

      /**
       * @param {object} dataSet
       * @returns {string|null}
       */

    }], [{
      key: "getLabel",
      value: function getLabel(dataSet) {
        if (dataSet.hasOwnProperty('label')) {
          return dataSet.label;
        }
        return null;
      }

      /**
       * @param {object} dataSet
       * @returns {function|null}
       */

    }, {
      key: "getAction",
      value: function getAction(dataSet) {
        if (dataSet.hasOwnProperty('action')) {
          return dataSet.action;
        }
        // backward compatibility
        if (dataSet.hasOwnProperty('onClick')) {
          return dataSet.onClick;
        }
        return null;
      }

      /**
       * @param {object} dataSet
       * @returns {object[]|null}
       */

    }, {
      key: "getItems",
      value: function getItems(dataSet) {
        if (dataSet.hasOwnProperty('items')) {
          if (typeof dataSet.items === 'function') {
            return dataSet.items();
          } else {
            return dataSet.items;
          }
        }
        return null;
      }
    }]);
    return ContextMenuFactory;
  }();

  var ContextMenuCanvas = function () {

    /**
     * @param {ContextMenu} contextMenu
     */
    function ContextMenuCanvas(contextMenu) {
      var _this2 = this;

      classCallCheck(this, ContextMenuCanvas);
      this.labelMargin = 12;
      this.borderColor = 'rgb(140, 140, 140)';
      this.borderStrokeWidth = '0.2px';
      this.drawMargin = 1;

      this.contextMenu = contextMenu;
      d3.select(document).on('click', function () {
        if (d3.select(_this2.contextMenu.elm.parentNode).classed('context-menu-unclickable')) {
          return;
        }
        d3.selectAll('.d3-v4-context-menu-container').remove();
      });
    }

    /**
     * @param {Number} x
     * @param {Number} y
     */


    createClass(ContextMenuCanvas, [{
      key: 'show',
      value: function show(x, y) {
        d3.selectAll('.d3-v4-context-menu-container').remove();
        this.render(x + this.drawMargin, y + this.drawMargin, this.contextMenu.getRootGroup());
      }

      /**
       * @param {int} x
       * @param {int} y
       * @param {ContextMenuGroup} group
       */

    }, {
      key: 'render',
      value: function render(x, y, group) {
        var _this3 = this;

        var _this = this;

        var groupItems = this.contextMenu.getItemsByGroup(group);

        var labelSizes = this.calculateLabelSize(groupItems);

        var width = d3.max(labelSizes.widths);

        var height = labelSizes.heights.reduce(function (sum, size) {
          return sum + size;
        });

        var container = d3.select('body').append('div').style('width', width + 'px').style('height', height + 'px').style('left', x + 'px').style('top', y + 'px').style('position', 'absolute').classed('d3-v4-context-menu-container', true).classed('d3-v4-context-menu-group-nested' + group.nestedIndex, true).attr('id', group.id);
        var g = container.append('svg').attr('width', '100%').attr('height', '100%').attr('x', 0).attr('y', 0).append('g');
        var contextMenu = g.selectAll('rect').data(groupItems);
        var contextItems = contextMenu.enter().append('svg').attr('class', 'item-entry').attr('id', function (item) {
          return item.id;
        }).attr('x', 0).attr('y', function (item, i) {
          return i * labelSizes.heights[i];
        }).attr('width', width).attr('height', function (item, i) {
          return labelSizes.heights[i];
        }).classed('context-menu-unclickable', function (item) {
          return item.action === null;
        });

        this.removeSameNestedGroups(group);

        contextItems.style('cursor', 'default');

        contextItems.on('mouseover', function (item) {
          var itemSelection = d3.select(this);
          var childGroup = _this.contextMenu.getGroupByParentItem(item);
          if (childGroup !== null) {
            if (!itemSelection.classed('child-group-visible')) {
              // show nested menu group
              itemSelection.classed('child-group-visible', true);
              _this.render(x + Number(itemSelection.attr('x')) + Number(itemSelection.attr('width')) - _this.drawMargin * 3, y + Number(itemSelection.attr('y')) + _this.drawMargin * 3, childGroup);
            }
          } else {
            // remove nested menu group
            _this.removeChildren(group);
          }
          itemSelection.select('rect').style("fill", item.onMouseoverFill);
        });

        contextItems.on('mouseout', function (item) {
          var itemSelection = d3.select(this);
          if (!itemSelection.classed('child-group-visible')) {
            // ignore parent of visible nested group
            itemSelection.select('rect').style("fill", item.defaultFill);
          }
        });

        contextItems.append('rect').style('fill', function (item) {
          return item.defaultFill;
        }).on('click', function (item) {
          return item.onClick(_this3.contextMenu.d, _this3.contextMenu.i, _this3.contextMenu.elm);
        }).attr('x', 0).attr('y', 0).attr('width', '100%').attr('height', '100%');
        contextItems.append('text').text(function (item) {
          return item.getLabel(_this3.contextMenu.d, _this3.contextMenu.i, _this3.contextMenu.elm);
        }).attr("class", "item-label").style("fill", "rgb").style("font-size", 11).on('click', function (item) {
          return item.onClick(_this3.contextMenu.d, _this3.contextMenu.i, _this3.contextMenu.elm);
        }).attr('x', '5px').attr('y', '50%');
        contextItems.append('text').text(function (item) {
          return _this3.contextMenu.getGroupByParentItem(item) !== null ? '>' : null;
        }).attr('x', '100%').attr('y', '50%').style("font-size", 11).attr('transform', 'translate(-12, 0)');

        this.drawBorder(g);
      }

      /**
       * @param {ContextMenuItem[]} groupItems
       * @returns {{widths: number, heights: number}}
       */

    }, {
      key: 'calculateLabelSize',
      value: function calculateLabelSize(groupItems) {
        var _this4 = this;

        var g = d3.select('body').append('svg').attr('class', 'd3-v4-dummy').append('g');
        var dummyContextMenu = g.selectAll('rect').data(groupItems);
        var dummyContextItems = dummyContextMenu.enter().append('svg').attr('class', 'dummy-item-entry');
        dummyContextItems.append('text').text(function (item) {
          return item.getLabel(_this4.contextMenu.d, _this4.contextMenu.i, _this4.contextMenu.elm) + (_this4.contextMenu.getGroupByParentItem(item) !== null ? ' >' : '');
        }).style("font-size", 11).attr('class', 'dummy-text');
        var dtext = d3.selectAll('.dummy-text');
        var size = {
          widths: dtext.nodes().map(function (node) {
            return node.getBBox().width + _this4.labelMargin;
          }),
          heights: dtext.nodes().map(function (node) {
            return node.getBBox().height + _this4.labelMargin;
          })
        };
        d3.selectAll('.d3-v4-dummy').remove();
        return size;
      }

      /**
       * @param {ContextMenuGroup} targetGroup
       */

    }, {
      key: 'removeSameNestedGroups',
      value: function removeSameNestedGroups(targetGroup) {
        var _this5 = this;

        this.contextMenu.getGroupsByNestedIndex(targetGroup.nestedIndex).map(function (group) {
          if (targetGroup === group) return;
          _this5.removeChildren(group);
          d3.select('#' + group.id).remove();
          d3.select('#' + group.parentItemId).classed('child-group-visible', false).select('rect').style("fill", function (item) {
            return item.defaultFill;
          });
        });
      }

      /**
       * @param {ContextMenuGroup} group
       */

    }, {
      key: 'removeChildren',
      value: function removeChildren(group) {
        var _this6 = this;

        this.contextMenu.getItemsByGroup(group).map(function (item) {
          var itemSelector = d3.select('#' + item.id);
          itemSelector.select('rect').style("fill", function (item) {
            return item.defaultFill;
          });
          itemSelector.classed('child-group-visible', false);
          var childGroup = _this6.contextMenu.getGroupByParentItem(item);
          if (childGroup === null) return;
          d3.select('#' + childGroup.id).remove();
          _this6.removeChildren(childGroup);
        });
      }

      /**
       * @param {d3.selection} groupSelection
       */

    }, {
      key: 'drawBorder',
      value: function drawBorder(groupSelection) {
        var groupBox = groupSelection.node().getBBox();
        groupSelection.append('rect').attr('x', groupBox.x).attr('y', groupBox.y).attr('width', groupBox.width).attr('height', groupBox.height).style("fill", "none").style('stroke', this.borderColor).style('stroke-width', this.borderStrokeWidth);
      }
    }]);
    return ContextMenuCanvas;
  }();

  var D3V4ContextMenu = function () {

    /**
     * @param {*} d
     * @param {number} i
     * @param {HTMLElement} elm
     * @param {object[]} dataSets
     */
    function D3V4ContextMenu(dataSets, d, i, elm) {
      classCallCheck(this, D3V4ContextMenu);

      var factory = new ContextMenuFactory();
      this.canvas = new ContextMenuCanvas(factory.factory(dataSets, d, i, elm));
    }

    /**
     * show the original context menu.
     */


    createClass(D3V4ContextMenu, [{
      key: "show",
      value: function show(x, y) {
        this.canvas.show(x, y);
      }
    }]);
    return D3V4ContextMenu;
  }();

  function d3V4Contextmenu (items) {
    return function (d, i) {
      d3.event.preventDefault();
      var d3V4ContextMenu = new D3V4ContextMenu(items, d, i, d3.event.target);
      d3V4ContextMenu.show(d3.event.pageX, d3.event.pageY);
    };
  }

  exports.contextmenu = d3V4Contextmenu;

  Object.defineProperty(exports, '__esModule', { value: true });

})));
