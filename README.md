Unsafe JAX-RS extension for Burp Suite
======================================

Unsafe JAX-RS is an active scanner extension for Burp Suite to check JAX-RS application for common security flaws. Currently following checks are implemented:
* Entity provider selection scan 
* WADL scan
* CSRF scan
* JSONP scan
* Async jobs scan
* DoS via GZIP bombing scan
* Content negotiation scan
* Exception mapping scan
	
Extension can identify following issues:
* CVE-2016-6346
* CVE-2016-8739
* CVE-2016-7050
* CVE-2016-6345
* CVE-2016-9571
* CVE-2016-6347
* CVE-2016-3720