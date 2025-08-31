## Permissions

Script-friendly octal permissions. Saves a bit of time when you would normally
need to parse a bunch of `stat` output to get what you need.

## Usage:

Check out the `/examples` directory:

### Extract permissions for chmod

```
# Get current permissions
perm=$(./permissions file myfile --octal-only | awk '{print $1}')
chmod "$perm" newfile

# Or in a pipeline:
find . -name "*.txt" -exec ./permissions file {} --octal-only \; | while read perm file; do
    echo "File $file has permissions $perm"
done
```

### Filter by file type

```
# Only process directories
./permissions dir /tmp --numeric-types | grep "^1 " | while read type perm name; do
    echo "Directory $name has permissions $perm"
done
```

### vs Stat

```
./permissions file /etc/passwd --octal-only
# Output: 644 /etc/passwd

# stat equivalent
stat -f "%Mp%Lp %N" /etc/passwd 2>/dev/null || stat --format="%a %n" /etc/passwd 2>/dev/null
# Output: 644 /etc/passwd
```

## Previous Version

I first wrote this in 2019 as a shell script (check out `archive/lp`).