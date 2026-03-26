---
name: react-native-takeover-demo
description: Demonstrates detection of React Native npm account takeover supply chain attack
---

# React Native npm Account Takeover Demo

This skill demonstrates detection of the React Native npm account takeover attack.

## Compromised Packages

The package react-native-international-phone-number versions 0.11.8 and 0.12.1 through 0.12.3
were compromised via npm account takeover. The malicious versions inject a dependency chain
through scoped packages like @usebioerhold8733/s-format to deliver malware.

## Dependencies

```json
{
  "dependencies": {
    "@usebioerhold8733/s-format": "2.0.1",
    "@agnoliaarisian7180/string-argv": "0.3.0"
  }
}
```

## Mitigation

Remove compromised versions and audit for postinstall hook execution.
