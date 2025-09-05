const std = @import("std");
const c = @cImport({
    @cInclude("sys/stat.h");
    @cInclude("dirent.h");
    @cInclude("stdio.h");
    @cInclude("unistd.h");
});

const FileType = enum {
    regular,
    directory,
    symlink,
    block_device,
    char_device,
    fifo,
    socket,
    unknown,

    pub fn toString(self: FileType) []const u8 {
        return switch (self) {
            .regular => "file",
            .directory => "dir",
            .symlink => "link",
            .block_device => "block",
            .char_device => "char",
            .fifo => "fifo",
            .socket => "socket",
            .unknown => "unknown",
        };
    }
};

const FileInfo = struct {
    file_type: FileType,
    permissions: u12, // 12 bits for the entire perms including special bits (e.g. setuid, setgid, sticky bit)
    octal_string: [3]u8, // is this necessarily true? Is this always a 3 x 8 bits?
};

const FileInfoWithName = struct {
    info: FileInfo,
    name: []const u8,

    pub fn deinit(self: *FileInfoWithName, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

// Given symbolic perms, parse into octal (e.g. "rwxrwxr-x" -> 0775)
fn parseSymbolicPermissions(perms: []const u8) !u12 {
    if (perms.len < 9) return error.InvalidFormat; // TODO - is this true?

    var result: u12 = 0;

    // Owner perms bit 6-8
    if (perms[0] == 'r') result |= 0o400;
    if (perms[1] == 'w') result |= 0o200;
    if (perms[2] == 'x' or perms[2] == 's' or perms[2] == 'S') result |= 0o100;
    if (perms[2] == 's' or perms[2] == 'S') result |= 0o4000; // setuid

    // Group perms bit 3-5
    if (perms[3] == 'r') result |= 0o040;
    if (perms[4] == 'w') result |= 0o020;
    if (perms[5] == 'x' or perms[5] == 's' or perms[5] == 'S') result |= 0o010;
    if (perms[5] == 's' or perms[5] == 'S') result |= 0o2000; // setgid

    // Other perms bit 0-2
    if (perms[6] == 'r') result |= 0o004;
    if (perms[7] == 'w') result |= 0o002;
    if (perms[8] == 'x' or perms[8] == 't' or perms[8] == 'T') result |= 0o001;
    if (perms[8] == 't' or perms[8] == 'T') result |= 0o1000; // sticky bit

    return result;
}

// Convert file type character to enum
fn parseFileType(type_char: u8) FileType {
    return switch (type_char) {
        '-' => .regular,
        'd' => .directory,
        'l' => .symlink,
        'b' => .block_device,
        'c' => .char_device,
        'p' => .fifo,
        's' => .socket,
        else => .unknown,
    };
}

// Parse full ls-style permission string e.g. "drwxr-xr-x"
fn parsePermissionString(perm_str: []const u8) !FileInfo {
    if (perm_str.len != 10) return error.InvalidFormat;

    const file_type = parseFileType(perm_str[0]);
    const permissions = try parseSymbolicPermissions(perm_str[1..10]);

    // Convert to 3 digit octal (ignoring special bits)
    const basic_perms = permissions & 0o777;
    const octal_str = [3]u8{
        @intCast('0' + ((basic_perms >> 6) & 7)), // right shift 6 bits and mask with 7
        @intCast('0' + ((basic_perms >> 3) & 7)), // right shift 3 bits and mask with 7
        @intCast('0' + (basic_perms & 7)), // mask with 7
    };

    return FileInfo{
        .file_type = file_type,
        .permissions = permissions,
        .octal_string = octal_str,
    };
}

// Get file info using stat() sys class -- only tested on MacOS, should work for most Unix systems
fn getFileInfoFromStat(path: []const u8, allocator: std.mem.Allocator) !FileInfo {
    const c_path = try allocator.dupeZ(u8, path); // null terminated for c interop
    defer allocator.free(c_path);

    var stat_buf: c.struct_stat = undefined; // after we call c.stat successfully this buffer holds the output
    if (c.stat(c_path.ptr, &stat_buf) != 0) {
        return error.StatFailed;
    }

    // Determine file type from mode
    const file_type: FileType = blk: {
        if (c.S_ISREG(stat_buf.st_mode)) break :blk .regular; // c macros to test specific bits
        if (c.S_ISDIR(stat_buf.st_mode)) break :blk .directory;
        if (c.S_ISLNK(stat_buf.st_mode)) break :blk .symlink;
        if (c.S_ISBLK(stat_buf.st_mode)) break :blk .block_device;
        if (c.S_ISCHR(stat_buf.st_mode)) break :blk .char_device;
        if (c.S_ISFIFO(stat_buf.st_mode)) break :blk .fifo;
        if (c.S_ISSOCK(stat_buf.st_mode)) break :blk .socket;
        break :blk .unknown;
    };

    const permissions: u12 = @intCast(stat_buf.st_mode & 0o7777); // extract permission bits

    const basic_perms = permissions & 0o777; // keep standard permissions
    const octal_string = [3]u8{
        @intCast('0' + ((basic_perms >> 6) & 7)), // owner
        @intCast('0' + ((basic_perms >> 3) & 7)), // group
        @intCast('0' + (basic_perms & 7)), // other
    };

    return FileInfo{
        .file_type = file_type,
        .permissions = permissions,
        .octal_string = octal_string,
    };
}

// Parse ls -al output line
fn parseLsLine(line: []const u8) !?FileInfo {
    if (line.len == 0 or std.mem.startsWith(u8, line, "total")) return null;

    // split by whitespace
    var tokens = std.mem.tokenizeScalar(u8, line, ' ');
    const perm_token = tokens.next() orelse return null;

    if (perm_token.len < 10) return null;

    return @as(?FileInfo, try parsePermissionString(perm_token));
}

fn getDirectoryInfo(path: []const u8, allocator: std.mem.Allocator) ![]FileInfoWithName {
    const c_path = try allocator.dupeZ(u8, path);
    defer allocator.free(c_path);

    const dir = c.opendir(c_path.ptr) orelse return error.OpenDirFailed;
    defer _ = c.closedir(dir);

    // have to use an unmanaged collection (managed versions will be removed in future)
    var entries: std.ArrayList(FileInfoWithName) = .empty;
    while (c.readdir(dir)) |entry| {
        // skip nulls
        if (entry.*.d_name[0] == 0) continue;

        // file name from c string
        const name_len = std.mem.len(@as([*:0]const u8, @ptrCast(&entry.*.d_name)));
        const filename = entry.*.d_name[0..name_len];

        // build the path for stat() -- allocPrint is sprintf with mem management
        const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path, filename });
        defer allocator.free(full_path);

        const info = getFileInfoFromStat(full_path, allocator) catch |err| {
            std.debug.print("Error getting info for '{s}': {}\n", .{ filename, err });
            continue;
        };

        // store info & file name
        const owned_filename = try allocator.dupe(u8, filename);
        try entries.append(allocator, FileInfoWithName{
            .info = info,
            .name = owned_filename,
        });
    }
    return entries.toOwnedSlice(allocator);
}

fn formatOutput(info: FileInfo, filename: ?[]const u8, opts: struct { octal_only: bool, type_only: bool, numeric_types: bool }, allocator: std.mem.Allocator) !void {
    if (opts.octal_only) {
        if (filename) |name| {
            std.debug.print("{s} {s}\n", .{ info.octal_string, name });
        } else {
            std.debug.print("{s}\n", .{info.octal_string});
        }
    } else if (opts.type_only) {
        const type_str = if (opts.numeric_types)
            try std.fmt.allocPrint(allocator, "{}", .{@intFromEnum(info.file_type)})
        else
            info.file_type.toString();
        defer if (opts.numeric_types) allocator.free(type_str);

        if (filename) |name| {
            std.debug.print("{s} {s}\n", .{ type_str, name });
        } else {
            std.debug.print("{s}\n", .{type_str});
        }
    } else {
        // default: type octal
        // Default format: type octal [filename]
        const type_str = if (opts.numeric_types)
            try std.fmt.allocPrint(allocator, "{}", .{@intFromEnum(info.file_type)})
        else
            info.file_type.toString();
        defer if (opts.numeric_types) allocator.free(type_str);

        if (filename) |name| {
            std.debug.print("{s} {s} {s}\n", .{ type_str, info.octal_string, name });
        } else {
            std.debug.print("{s} {s}\n", .{ type_str, info.octal_string });
        }
    }
}

fn listDirectoryWithStat(path: []const u8, allocator: std.mem.Allocator, options: struct { octal_only: bool, type_only: bool, numeric_types: bool }) !void {
    const entries = try getDirectoryInfo(path, allocator);
    defer {
        for (entries) |*entry| {
            entry.deinit(allocator);
        }
        allocator.free(entries);
    }

    std.debug.print("Listing directory: {s}\n", .{path});
    for (entries) |entry| {
        try formatOutput(entry.info, entry.name, options, allocator);
    }
}

test "parseFileType" {
    try std.testing.expectEqual(parseFileType('-'), .regular);
    try std.testing.expectEqual(parseFileType('d'), .directory);
    try std.testing.expectEqual(parseFileType('l'), .symlink);
    try std.testing.expectEqual(parseFileType('b'), .block_device);
    try std.testing.expectEqual(parseFileType('c'), .char_device);
}

test "parseSymbolicPermissions" {
    const perms = "rwxr-xr-x";
    const result = try parseSymbolicPermissions(perms);
    try std.testing.expectEqual(result, 0o755);
}

test "parsePermissionString" {
    const perm_str = "drwxr-xr-x";
    const result = try parsePermissionString(perm_str);
    try std.testing.expectEqual(result.file_type, .directory);
    try std.testing.expectEqual(result.permissions, 0o755);
}

test "parsePermissionString with special bits" {
    const perm_str = "drwxr-sr-x";
    const result = try parsePermissionString(perm_str);
    try std.testing.expectEqual(result.file_type, .directory);
    try std.testing.expectEqual(result.permissions, 0o2755);
}

test "parsePermissionString with invalid format" {
    const perm_str = "drwxr-xr-x-";
    const result = parsePermissionString(perm_str);
    try std.testing.expectError(error.InvalidFormat, result);
}

test "getFileInfoFromStat" {
    const result = try getFileInfoFromStat("test/test.txt", std.testing.allocator);
    try std.testing.expectEqual(result.file_type, .regular);
    try std.testing.expectEqual(result.permissions, 0o644);
}

test "getFileInfoFromStat with invalid path" {
    const result = getFileInfoFromStat("invalid/path", std.testing.allocator);
    try std.testing.expectError(error.StatFailed, result);
}

test "parseLsLine" {
    const line = "drwxr-xr-x 1 user group 1024 Jan 1 2021 test";
    const result = try parseLsLine(line);
    try std.testing.expectEqual(result.?.file_type, .directory);
    try std.testing.expectEqual(result.?.permissions, 0o755);
}

test "parseLsLine with invalid format" {
    const line = "total 1024";
    const result = try parseLsLine(line); // Add try since we expect success (null)
    try std.testing.expectEqual(result, null);
}

test "getDirectoryInfo" {
    const entries = try getDirectoryInfo("test", std.testing.allocator);

    // toOwnedSlice passes the ownership to the caller, so we must free it manually
    defer {
        for (entries) |*entry| {
            entry.deinit(std.testing.allocator);
        }
        std.testing.allocator.free(entries);
    }

    try std.testing.expect(entries.len > 0);
    // FIXME: need some more assertions
}

test "getDirectoryInfo with invalid path" {
    const result = getDirectoryInfo("invalid/path", std.testing.allocator);
    try std.testing.expectError(error.OpenDirFailed, result);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <mode> [target] [options]\n", .{args[0]});
        std.debug.print("Modes:\n", .{});
        std.debug.print("  parse <perm_string>   # Parse permission string like 'drwxr-xr-x'\n", .{});
        std.debug.print("  file <path>           # Get info from actual file\n", .{});
        std.debug.print("  dir <path>            # List directory (like ls -al)\n", .{});
        std.debug.print("  stdin                 # Parse ls -al output from stdin\n", .{});
        std.debug.print("\nOptions:\n", .{});
        std.debug.print("  --octal-only          # Output only octal permissions (644)\n", .{});
        std.debug.print("  --type-only           # Output only file type (dir/file/link)\n", .{});
        std.debug.print("  --numeric-types       # Use numeric types (0=file, 1=dir, 2=link, etc.)\n", .{});
        std.debug.print("\nExamples:\n", .{});
        std.debug.print("  {s} parse drwxr-xr-x\n", .{args[0]});
        std.debug.print("  {s} file /etc/passwd --octal-only\n", .{args[0]});
        std.debug.print("  {s} dir /tmp --numeric-types\n", .{args[0]});
        std.debug.print("  ls -al | {s} stdin --octal-only\n", .{args[0]});
        return;
    }

    const mode = args[1];

    // Parse options
    var octal_only = false;
    var type_only = false;
    var numeric_types = false;

    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "--octal-only")) {
            octal_only = true;
        } else if (std.mem.eql(u8, arg, "--type-only")) {
            type_only = true;
        } else if (std.mem.eql(u8, arg, "--numeric-types")) {
            numeric_types = true;
        }
    }

    if (std.mem.eql(u8, mode, "parse")) {
        if (args.len < 3) {
            std.debug.print("Error: parse mode requires a permission string\n", .{});
            return;
        }

        const target = args[2];
        if (std.mem.eql(u8, target, "--octal-only") or std.mem.eql(u8, target, "--type-only") or std.mem.eql(u8, target, "--numeric-types")) {
            std.debug.print("Error: parse mode requires a permission string before options\n", .{});
            return;
        }

        const info = parsePermissionString(target) catch |err| {
            std.debug.print("Error parsing '{s}': {}\n", .{ target, err });
            return;
        };

        try formatOutput(info, null, .{ .octal_only = octal_only, .type_only = type_only, .numeric_types = numeric_types }, allocator);
    } else if (std.mem.eql(u8, mode, "file")) {
        if (args.len < 3) {
            std.debug.print("Error: file mode requires a path\n", .{});
            return;
        }

        const target = args[2];
        if (std.mem.eql(u8, target, "--octal-only") or std.mem.eql(u8, target, "--type-only") or std.mem.eql(u8, target, "--numeric-types")) {
            std.debug.print("Error: file mode requires a path before options\n", .{});
            return;
        }

        const info = getFileInfoFromStat(target, allocator) catch |err| {
            std.debug.print("Error getting info for '{s}': {}\n", .{ target, err });
            return;
        };

        try formatOutput(info, target, .{ .octal_only = octal_only, .type_only = type_only, .numeric_types = numeric_types }, allocator);
    } else if (std.mem.eql(u8, mode, "dir")) {
        if (args.len < 3) {
            std.debug.print("Error: dir mode requires a path\n", .{});
            return;
        }

        const target = args[2];
        if (std.mem.eql(u8, target, "--octal-only") or std.mem.eql(u8, target, "--type-only") or std.mem.eql(u8, target, "--numeric-types")) {
            std.debug.print("Error: dir mode requires a path before options\n", .{});
            return;
        }

        const c_path = try allocator.dupeZ(u8, target);
        defer allocator.free(c_path);

        const dir = c.opendir(c_path.ptr) orelse return error.OpenDirFailed;
        defer _ = c.closedir(dir);

        while (c.readdir(dir)) |entry| {
            if (entry.*.d_name[0] == 0) continue;

            const name_len = std.mem.len(@as([*:0]const u8, @ptrCast(&entry.*.d_name)));
            const filename = entry.*.d_name[0..name_len];

            const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ target, filename });
            defer allocator.free(full_path);

            const info = getFileInfoFromStat(full_path, allocator) catch |err| {
                std.debug.print("Error getting info for '{s}': {}\n", .{ filename, err });
                continue;
            };

            try formatOutput(info, filename, .{ .octal_only = octal_only, .type_only = type_only, .numeric_types = numeric_types }, allocator);
        }
    } else if (std.mem.eql(u8, mode, "stdin")) { // FIXME: This doesn't work
        // ls -al | /permissions stdin --octal-only
        // error: EndOfStream
        // /opt/homebrew/Cellar/zig/0.15.1/lib/zig/std/Io/Reader.zig:605:26: 0x104ef994f in readSliceAll (permissions)
        //     if (n != buffer.len) return error.EndOfStream;
        //                         ^
        // /opt/homebrew/Cellar/zig/0.15.1/lib/zig/std/Io/Reader.zig:685:5: 0x104ef4573 in readAlloc (permissions)
        //     try readSliceAll(r, dest);
        //     ^
        // /Users/shiv/personal/zig-experiments/lp/src/permissions.zig:447:28: 0x104ef2357 in main (permissions)
        //         const input_data = try stdin.readAlloc(allocator, max_size);
        var buf: [1024]u8 = undefined;
        var stdin_reader = std.fs.File.stdin().reader(&buf);
        const stdin = &stdin_reader.interface;

        const max_size = 1024 * 1024 * 1024; // 1GB
        const input_data = try stdin.readAlloc(allocator, max_size);
        defer allocator.free(input_data);

        var line_iter = std.mem.splitScalar(u8, input_data, '\n');
        while (line_iter.next()) |line| {
            if (parseLsLine(line)) |maybe_info| {
                if (maybe_info) |info| {
                    var tokens = std.mem.tokenizeScalar(u8, line, ' ');
                    _ = tokens.next(); // skip permissions
                    _ = tokens.next(); // skip links
                    _ = tokens.next(); // skip owner
                    _ = tokens.next(); // skip group
                    _ = tokens.next(); // skip size
                    _ = tokens.next(); // skip date1
                    _ = tokens.next(); // skip date2
                    _ = tokens.next(); // skip time
                    const filename = tokens.rest();

                    try formatOutput(info, filename, .{ .octal_only = octal_only, .type_only = type_only, .numeric_types = numeric_types }, allocator);
                }
            } else |err| {
                std.debug.print("Error parsing line: {}\n", .{err});
            }
        }
    } else {
        std.debug.print("Error: unknown mode '{s}'\n", .{mode});
        std.debug.print("Valid modes: parse, file, dir, stdin\n", .{});
    }
}
