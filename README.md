# retroCSP

retroCSP is a browser-independent retrofitting architecture based on a ServiceWorker that retrofits non-universally supported CSP features on the client side.
It allows developers to utilize newest CSP features while assuring that they will be enforced consistently by all modern browsers.
With retroCSP, developers are able to deploy policies that do not require hacks to allow for compatibility, which sacrifices security.
retroCSP retrofits the 'strict-dynamic' and 'unsafe-hashes' source-expressions as well as the navigate-to directive.

To deploy retroCSP, you have to host the ServiceWorker yourself at the root directory of your Website, and your whole Website has to support HTTPS. 
This repository also contains two alternative ServiceWorker registration scripts. service_worker_registration.js, if included in a Website, registers the ServiceWorker for a client and automatically reloads the page as soon as the ServiceWorker is successfully installed such that even the current session of the client will be governed by retroCSP. 
The light version only registers retroCSP. 
The ServiceWorker will only start retrofitting when the client establishes a new connection (closes all tabs and reloads page).
