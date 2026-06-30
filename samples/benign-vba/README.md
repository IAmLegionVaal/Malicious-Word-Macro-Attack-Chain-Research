# Benign VBA sample

`ThisDocument.cls` demonstrates the `Document_Open` event without spawning a process or using the network.

Expected result:

```text
%TEMP%\office-macro-lab-marker.txt
```

Use only in a disposable lab document. Do not weaken enterprise Office policy to run this sample on production endpoints.
