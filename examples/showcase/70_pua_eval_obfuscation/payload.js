// Showcase: Unicode PUA / variation-selector obfuscation near dynamic execution sinks
const payload = "console.log('run')";
// Variation selectors appended adjacent to eval sink should trigger OBF-003
const run = eval(payload)️️;

// Also include supplementary variation selectors adjacent to Function sink
const f = 󠄀󠄁Function("return 42");
