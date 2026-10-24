# Provider coverage

For each of 743 providers that TruffleHog has a detector and example credentials for, does the tool report anything in that provider's test folder? Example strings are TruffleHog's, so this measures breadth of recognised providers, not accuracy. TruffleHog itself recognises all of them by construction and is not scored here.

| Tool | Providers recognised | Share |
| --- | --- | --- |
| Tripwire | 347 | 46.7% |
| Gitleaks 8.30.1 | 351 | 47.2% |

Recognised only by Tripwire: 25. Recognised only by Gitleaks: 29. Recognised by neither: 367.

Neither tool recognises (first 40): aiven, apacta, api2cart, appfollow, azuresastoken, baremetrics, beamer, besttime, betterstack, bulksms, calendlyapikey, checkvist, cloudconvert, cloudinary, cloze, codemagic, coinlib, convertkit, couchbase, currencycloud, d7network, debounce, discordwebhook, dotdigital, eagleeyenetworks, edenai, formio, front, ftp, gocanvas, graphcms, helpcrunch, host, ibmclouduserkey, iconfinder, iexapis, iexcloud, imagekit, imagga, impala, …

Read this as: Tripwire is level with Gitleaks (it ships Gitleaks' rules) and well short of TruffleHog's breadth. Many of the unrecognised providers use bare, context-free token formats that no pattern scanner can tell apart from random text without a verification call; TruffleHog covers them by calling the provider.
