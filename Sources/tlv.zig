
const std = @import("std");

/// Tag/length encoding type, either a fixed amount of bytes or a special
/// encoding.
/// TODO: ULEB128 and vlq types
pub const EncodingType = union(enum) {
    /// bytes
    fixed_little: type,
    /// bytes
    fixed_big: type 
};

pub fn Tlv(comptime TagType: type, comptime encodingType: EncodingType) type {
    return struct {

        const HeaderInt = switch (encoding) {
            inline .fixed_little, .fixed_big => |Type| Type
        };

        comptime {
            if (@typeInfo(Tag) != .@"enum")
                @compileError("Tag type must be an enum, not " ++ @typeName(Tag));
            if (@typeInfo(HeaderInt) != .int)
                @compileError("Encoding type must have an underlying integer type, not " ++ @typeName(HeaderInt));
            if (@typeInfo(@typeInfo(Tag).@"enum".tag_type).int.bits < @typeInfo(HeaderInt).int.bits)
                @compileError("Underlying encoding integer has a larger bitwidth than tag type " ++ @typeName(Tag));
            if (@typeInfo(HeaderInt).int.signedness != .unsigned)
                @compileError("Underlying encoding integer may not be signed");
        }

        pub const Message = struct {

            tag: Tag,
            length: HeaderInt,
            value: []const u8,

            // TODO: Static and dynamic modes
            pub fn deinit(self: *const Message, allocator: std.mem.Allocator) void {
                // first expand the value to use its entire capacity before
                // attempting to deallocate it
                var buffer = self.value;
                buffer.len = self.length;
                allocator.free(buffer);
            }

            pub fn is_complete(self: *const Message) bool {
                return self.length == self.value.len;
            }
        };

        pub const Tag = TagType;
        pub const encoding = encodingType;

        pub fn read(allocator: std.mem.Allocator, reader: anytype) !Message {
            const tag = try read_head(reader);
            const length = try read_head(reader);

            var buffer = try allocator.alloc(u8, length);
            var write_buffer = buffer;
            var write_len: usize = 0;

            while (write_buffer.len != 0 and buffer.len != 0) {
                const len = try reader.read(write_buffer);
                if (len == 0) break;
                write_buffer = write_buffer[len..];
                write_len += len;
            }

            return .{
                .tag = @enumFromInt(tag),
                .length = length,
                .value = buffer[0..write_len] };
        }

        fn read_head(reader: anytype) !HeaderInt {
            return switch (encoding) {
                .fixed_little => try reader.readInt(HeaderInt, .little),
                .fixed_big => try reader.readInt(HeaderInt, .big)
            };
        }

        pub fn write(tag: Tag, value: []const u8, inner_writer: anytype) !void {
            if (value.len > std.math.maxInt(HeaderInt))
                return error.PayloadTooLarge;
            var buffer = std.io.bufferedWriter(inner_writer);
            const writer = buffer.writer();

            try write_bytes(HeaderInt, @intFromEnum(tag), writer);
            try write_bytes(HeaderInt, @intCast(value.len), writer);
            try writer.writeAll(value);
            try buffer.flush();
        }

        fn write_bytes(comptime T: type, integer: T, writer: anytype) !void {
            const bytes = @bitSizeOf(T) / 8; // @sizeOf() returns 4 for u24
            var byte: usize = 0;

            switch (encoding) {
                .fixed_little => while (byte < bytes) : (byte += 1) {
                    const shift = byte * 8;
                    const value: u8 = @truncate((integer >> @intCast(shift)) & 0xFF);
                    try writer.writeByte(value);
                },
                .fixed_big => while (byte < bytes) : (byte += 1) {
                    const shift = (bytes - byte - 1) * 8;
                    const value: u8 = @truncate((integer >> @intCast(shift)) & 0xFF);
                    try writer.writeByte(value);
                }
            }
        }
    };
}

// Tests

const TestTag32 = enum(u32) {
    one,
    two,
    three,
    _
};

const TestTag16 = enum(u16) {
    one,
    two,
    three,
    _
};

test "read" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x01, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0xEA });
    const TlvInstance = Tlv(TestTag32, .{ .fixed_little = u32 });
    const message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag32.two, message.tag);
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqual(@as(usize, 4), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, message.value);
    try std.testing.expect(message.is_complete());
}

test "read big" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04, 0xEA });
    const TlvInstance = Tlv(TestTag32, .{ .fixed_big = u32 });
    const message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag32.two, message.tag);
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqual(@as(usize, 4), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, message.value);
    try std.testing.expect(message.is_complete());
}

test "read subsequent" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x01, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04,
        0x01, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0xDE, 0xAD, 0xBE, 0xAF });
    const TlvInstance = Tlv(TestTag32, .{ .fixed_little = u32 });
    const message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag32.two, message.tag);
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqual(@as(usize, 4), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, message.value);
    try std.testing.expect(message.is_complete());

    const other_message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    defer other_message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag32.two, other_message.tag);
    try std.testing.expectEqual(@as(u32, 4), other_message.length);
    try std.testing.expectEqual(@as(usize, 4), other_message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xAF }, other_message.value);
    try std.testing.expect(other_message.is_complete());
}

test "read zero" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF });
    const TlvInstance = Tlv(TestTag16, .{ .fixed_little = u16 });
    const message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag16.two, message.tag);
    try std.testing.expectEqual(@as(u32, 0), message.length);
    try std.testing.expectEqual(@as(usize, 0), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{}, message.value);
    try std.testing.expect(message.is_complete());

    // TODO: Zero length misreads second message
    // const other_message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    // defer other_message.deinit(std.testing.allocator);

    // try std.testing.expectEqual(TestTag16.three, message.tag);
    // try std.testing.expectEqual(@as(u32, 4), message.length);
    // try std.testing.expectEqual(@as(usize, 4), message.value.len);
    // try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, message.value);
    // try std.testing.expect(message.is_complete());
}

test "read incomplete" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x01, 0x00,
        0x08, 0x00,
        0x01, 0x02, 0x03, 0x04 });
    const TlvInstance = Tlv(TestTag16, .{ .fixed_little = u16 });
    const message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag16.two, message.tag);
    try std.testing.expectEqual(@as(u32, 8), message.length);
    try std.testing.expectEqual(@as(usize, 4), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, message.value);
    try std.testing.expect(!message.is_complete());
}

test "write" {
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();
    const TlvInstance = Tlv(TestTag16, .{ .fixed_little = u16 });
    try TlvInstance.write(.three, "Hello world!", output.writer());

    try std.testing.expectEqualSlices(u8, &.{
        0x02, 0x00, // .three
        0x0C, 0x00, // "Hello world!".len
        'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'
    }, output.items);
}

test "write big" {
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();
    const TlvInstance = Tlv(TestTag16, .{ .fixed_big = u16 });
    try TlvInstance.write(.three, "Hello world!", output.writer());

    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x02, // .three
        0x00, 0x0C, // "Hello world!".len
        'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'
    }, output.items);
}

test "read/write roundtrip" {
    const Tag = enum(u32) {
        chown,
        chmod,
        chroot,
        _
    };

    const TlvInstance = Tlv(Tag, .{ .fixed_little = u32 });

    var protocol = std.ArrayList(u8).init(std.testing.allocator);
    defer protocol.deinit();

    try TlvInstance.write(.chroot, "/foo", protocol.writer());

    var buffer = std.io.fixedBufferStream(protocol.items);
    const message = try TlvInstance.read(std.testing.allocator, buffer.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(Tag.chroot, message.tag);
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqualSlices(u8, "/foo", message.value);
    try std.testing.expect(message.is_complete());
}
