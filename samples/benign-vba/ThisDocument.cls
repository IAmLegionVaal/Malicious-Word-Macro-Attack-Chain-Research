Option Explicit

' Benign telemetry marker only.
' Place this code in the ThisDocument class module of a disposable lab document.
' It does not start a process, use PowerShell, connect to a network, or download content.

Private Sub Document_Open()
    WriteBenignLabMarker
End Sub

Private Sub WriteBenignLabMarker()
    On Error GoTo Handler

    Dim markerPath As String
    Dim fileHandle As Integer

    markerPath = Environ$("TEMP") & "\office-macro-lab-marker.txt"
    fileHandle = FreeFile

    Open markerPath For Append As #fileHandle
    Print #fileHandle, Format$(Now, "yyyy-mm-dd hh:nn:ss") & " - benign Document_Open marker"
    Close #fileHandle

    Exit Sub

Handler:
    On Error Resume Next
    If fileHandle > 0 Then Close #fileHandle
    MsgBox "Benign lab marker failed: " & Err.Description, vbExclamation
End Sub
