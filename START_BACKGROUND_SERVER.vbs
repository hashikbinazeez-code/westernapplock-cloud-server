Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
currentDir = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.Run "cmd /c cd /d """ & currentDir & """ && node server.js", 0, False
WScript.Sleep 2500
WshShell.Run "https://is.gd/westernintapplock"
