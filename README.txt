CodeProbe v2 transparent package
================================

Files
-----
- index.html : browser interface
- engine.py : readable Python analysis engine
- run_local_server.py : optional helper for local serving

Recommended launch
------------------
1. Keep index.html and engine.py in the same folder.
2. Run:
   python run_local_server.py
3. Open the reported address in a modern browser.

Direct opening
--------------
You can also open index.html directly from the file system.
If the browser blocks relative file loading, click 'Load engine file'
and select the bundled engine.py file when prompted.

Notes
-----
- Internet access is still required for the Pyodide runtime, which is
  loaded from the official CDN.
- The application stores only local report history in the browser.
- The source code being analysed is not uploaded anywhere by this package.
