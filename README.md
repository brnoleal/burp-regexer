# Regexer

Burp extension to regex everything that you want.

## Requirements

You gonna need Jython (standalone version), which you can get at https://www.jython.org/download.html. For more information about how to install jython extensions in Burp visit: https://portswigger.net/support/how-to-install-an-extension-in-burp-suite

## Some notes:

- When update button is used only messages into proxy history are processed, being so, values previously matched from other tools, like repeater and intruder will be lost and not processed.
- The results are extract from group 0 of regex, so, be carefull with your regex.
- The regex rules are locally save at:
    - Linux: /tmp/regexer-rules.json
    - Windows: C:\\WINDOWS\\Temp\\regexer-rules.json

## Some regex references: 

https://github.com/hahwul/RegexPassive
https://github.com/zricethezav/gitleaks
https://github.com/l4yton/RegHex
https://gist.github.com/h4x0r-dz/be69c7533075ab0d3f0c9b97f7c93a59
https://github.com/sdushantha/dora/blob/main/dora/db/data.json

## TODO

- [ ] Include Enable/Disable option for rules;
- [ ] Include option to process only items that match targets in Scope;
- [ ] Fix where to store regex locally in MacOs.
