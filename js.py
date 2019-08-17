# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Includes all third-party javascript files."""

# This includes the javascript code common to all transperf pages.
TRANSPERF = r'''
var in_iframe = function() {
    return window.self !== window.top;
};

var top_doc = function() {
    return in_iframe() ? window.top.document : window.document;
};

var headline = function(text) {
    var h = $('<h1>' + text + '</h1>');
    h.css('color', 'yellow');
    return h;
};

document.show_help = function() {
    var document = top_doc();
    var help = $('<div id="help" />');
    help.css('position', 'absolute')
        .css('background', 'white')
        .css('opacity', '.85')
        .css('top', '0')
        .css('left', '0')
        .css('width', '100%')
        .css('height', '100%')
        .css('z-index', '1000');

    var content = $('<div/>');
    content.css('background', 'black')
           .css('border-radius', '10px')
           .css('color', 'white')
           .css('vertical-align', 'middle')
           .css('width', '80%')
           .css('height', '80%')
           .css('margin', 'auto')
           .css('margin-top', '1%')
           .css('padding', '5%');

    content.append(headline('All Graphs'));
    content.append(
            '<div><b>Move Graph</b>: &lt;SHIFT&gt; drag with mouse</div>');
    content.append(
            '<div><b>Vertical Zoom</b>: Drag area vertically</div>');
    content.append(
            '<div><b>Horizontal Zoom</b>: Drag area horitontally</div>');
    content.append('<div><b>Reset Zoom</b>: Double click</div>');

    content.append(headline('Klog Graphs'));
    content.append('<div><b>Maximize</b>: ' +
                   'Press the (+) button next to each graph</div>');
    content.append('<div><b>Undo Maximize</b>: ' +
                   'Press the (-) button next to each graph</div>');


    help.append(content);

    $(document.body).append(help);
    document.transperf_help_div = help;
};

document.hide_help = function(){
    var document = top_doc();
    $(document.transperf_help_div).remove();
    document.traansperf_help_div = null;
};

// Install the key listener on the parent frame.
$(document).on('keydown', function (e) {
    var keycode = e.keyCode || e.which;
    // Question mark.
    switch(keycode) {
      case 191:
	document.hide_help();
	document.show_help();
	return;
      case 27:
	document.hide_help();
	return;
    }
});
'''

# jQuery v2.1.3 (minified) fetched from
# https://code.jquery.com/jquery-2.1.3.min.js on Jan 12, 2015.
with open("third_party/jquery/jquery-2.1.3.min.js", "r") as f:
    JQUERY = f.read()

# Dygraphs v2.1.0 CSS fetched from
# http://dygraphs.com/2.1.0/dygraph.css on 2019-07-16
with open("third_party/dygraphs/dygraph.css", "r") as f:
    DYGRAPHS_CSS = f.read()

# Dygraphs v2.1.0 (minified) fetched from
# http://dygraphs.com/2.1.0/dygraph.min.js on 2019-07-16.
with open("third_party/dygraphs/dygraph.min.js", "r") as f:
    DYGRAPHS_MIN = f.read()

# Dygraphs Shapes Plugin v2.1.0 fetched from
# http://dygraphs.com/extras/shapes.js on 2019-07-16.
with open("third_party/dygraphs/shapes.js", "r") as f:
    DYGRAPHS_SHAPES = f.read()

# Dygraphs Synchronize Plugin v2.1.0 fetch from
# http://dygraphs.com/extras/synchronizer.js on 2019-07-16.
with open("third_party/dygraphs/synchronizer.js", "r") as f:
    DYGRAPHS_SYNC = f.read()

DYGRAPHS = "\n".join((DYGRAPHS_MIN, DYGRAPHS_SHAPES, DYGRAPHS_SYNC))
