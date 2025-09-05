## Permissions

Script-friendly octal permissions. Saves a bit of time when you would normally
need to parse a bunch of `stat` output to get what you need.

## Usage:

```
% ./permissions 
Usage: ./permissions <mode> [target] [options]
Modes:
  parse <perm_string>   # Parse permission string like 'drwxr-xr-x'
  file <path>           # Get info from actual file
  dir <path>            # List directory (like ls -al)
  stdin                 # Parse ls -al output from stdin

Options:
  --octal-only          # Output only octal permissions (644)
  --type-only           # Output only file type (dir/file/link)
  --numeric-types       # Use numeric types (0=file, 1=dir, 2=link, etc.)

Examples:
  ./permissions parse drwxr-xr-x
  ./permissions file /etc/passwd --octal-only
  ./permissions dir /tmp --numeric-types
  ls -al | ./permissions stdin --octal-only
```


## Previous Version

I first wrote this in 2019 as a shell script (check out `archive/lp`).