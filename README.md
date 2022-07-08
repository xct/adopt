# Adopt

This tool can run a process from another process. This is useful when you are running in session 0 (e.g. WinRM) and can't start any session > 0 processes. 
If there is another process running as the same user in a higher session, we can use it to run any binary in that session.

In 99% of cases you want to use explorer.exe as the target process (it requires the target process to have ShellExecuteExW imported, which explorer does).

## Usage

```
Example Usage:
adopt.exe explorer.exe C:\\windows\\system32\\cmd.exe
```