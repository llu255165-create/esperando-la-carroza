#!/usr/bin/env python3
"""
Recalcula los «hashes» de la política de seguridad (CSP) de index.html.

La web no permite código en línea «a ciegas»: el navegador solo ejecuta el <style> y los <script>
cuyo hash figura en la etiqueta <meta http-equiv="Content-Security-Policy"> del <head>.
Por eso, cada vez que edites a mano el CSS o el JavaScript de index.html, hay que correr:

    python3 actualizar-csp.py            (o:  python3 actualizar-csp.py ruta/a/index.html)

El script actualiza solo el hash en la etiqueta del <head>; no toca nada más.
"""
import base64, hashlib, re, sys
from html.parser import HTMLParser

ruta = sys.argv[1] if len(sys.argv) > 1 else 'index.html'
html = open(ruta, encoding='utf-8').read()


class Buscador(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.actual = None
        self.bloques = {'script': [], 'style': []}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'style' or (tag == 'script' and 'src' not in a and a.get('type', 'text/javascript') in ('text/javascript', 'module')):
            self.actual = [tag, []]

    def handle_data(self, data):
        if self.actual:
            self.actual[1].append(data)

    def handle_endtag(self, tag):
        if self.actual and self.actual[0] == tag:
            self.bloques[tag].append(''.join(self.actual[1]))
            self.actual = None


def sha(texto):
    t = texto.replace('\r\n', '\n')
    return "'sha256-" + base64.b64encode(hashlib.sha256(t.encode('utf-8')).digest()).decode() + "'"


b = Buscador()
b.feed(html)
hashes = {k: [sha(t) for t in v] for k, v in b.bloques.items()}

m = re.search(r'(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(")', html)
if not m:
    sys.exit('No encontré la etiqueta Content-Security-Policy en ' + ruta)

directivas = [d.strip() for d in m.group(2).split(';') if d.strip()]
nuevas, vistas = [], set()
for d in directivas:
    nombre, *tokens = d.split()
    vistas.add(nombre)
    clave = {'script-src': 'script', 'style-src': 'style'}.get(nombre)
    if clave:
        resto = [t for t in tokens if t != "'self'" and t != "'unsafe-inline'" and not t.startswith("'sha256-")]
        d = ' '.join([nombre, "'self'"] + hashes[clave] + resto)
    nuevas.append(d)
if 'object-src' not in vistas:
    nuevas.append("object-src 'none'")

html = html[:m.start(2)] + '; '.join(nuevas) + html[m.end(2):]
open(ruta, 'w', encoding='utf-8').write(html)
print('CSP actualizada en', ruta)
print('  <script> en línea:', len(hashes['script']), '· <style> en línea:', len(hashes['style']))
