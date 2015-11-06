# WcfScan
A tool for scanning NET.TCP WCF endpoints to test the security of their binding configurations.

This code creates a very simple, generic service contract and attempts to connect to the supplied service endpoint URL, cycling through all of the possible security setting options. Ultimately, the generic contract will not make a successful end-to-end call to the service; however, it will work just fine for enumerating the security settings by interpreting the exceptions that the .NET framework returns. This allows the tester to focus on the results rather than write boilerplate code that is only needed for a few minutes. For the tester who is unfamiliar with development in .NET, WcfScan can help to quickly assess basic security configuration settings for a NET.TCP service binding.

Usage is simple: WcfScan.exe net.tcp://[host]:[port]/[path]
