
pub fn read(comptime T: type, reader: anytype) !T {
    var result: T = 0;
    var shift: T = 0;

    while (true) : (shift += 7) {
        if (shift >= @bitSizeOf(T)) return error.LengthOverflow;
        const byte: T = @intCast(try reader.readByte());
        result |= (byte & 0x7F) << @truncate(shift);
        if (byte & 0x80 == 0) return result;
    }
}

pub fn write(comptime T: type, integer: T, writer: anytype) !void {
    if (integer == 0)
        return try writer.writeByte(0);
    var value = integer;

    while (value != 0) {
        var emitting_byte: u8 = @truncate(value & 0x7F);
        value >>= 7;
        if (value != 0) emitting_byte |= 0x80;
        try writer.writeByte(emitting_byte);
    }
}

// Tests

const std = @import("std");

test read {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 { 0x81, 0x01, });
    try std.testing.expectEqual(@as(u32, 129), read(u32, test_buffer.reader()));
}

test "overflow" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x80, 0x80, 0x80, 0x80,
        0x80, 0x00 });
    try std.testing.expectError(error.LengthOverflow, read(u32, test_buffer.reader()));
}

test write {
    var outgoing = std.ArrayList(u8).init(std.testing.allocator);
    defer outgoing.deinit();
    try write(u32, 624485, outgoing.writer());
    try std.testing.expectEqualSlices(u8, &.{ 0xE5, 0x8E, 0x26 }, outgoing.items);
}
