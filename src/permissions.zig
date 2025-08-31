const std = @import("std");

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

test "parseSymbolicPermissions" {
    const perms = "rwxr-xr-x";
    const result = try parseSymbolicPermissions(perms);
    try std.testing.expectEqual(result, 0o755);
}

pub fn main() !void {
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
}
