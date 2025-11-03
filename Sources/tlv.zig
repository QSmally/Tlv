
const std = @import("std");

/// Tag/length encoding type, either a fixed amount of bytes or a special
/// encoding.
pub const EncodingType = union(enum) {
    /// Fixed-width bytes
    fixed_little: type,
    /// Fixed-width bytes
    fixed_big: type,
    /// ULEB128 (Little Endian Base 128) is variable-length
    uleb128
};

pub const ReadOptions = struct {
    /// Return error.InvalidTag if the TLV message tag doesn't
    /// correspond to a tag in the backing enum.
    exhaustive_tags: bool = false,
    /// Parse and discard the rest of the message if error.InvalidTag
    /// occurs. This means that invalid tags are interpreted as version
    /// mismatches instead of malformed bytes.
    discard: bool = false,
    /// Return error.PayloadTooLarge if the TLV message has a length
    /// greater than this value. Always discards the payload.
    max_size: usize = 4096
};

pub const uleb128 = @import("uleb128.zig");

pub fn Tlv(comptime TagType: type, comptime encodingType: EncodingType) type {
    return struct {

        const HeaderInt = switch (encoding) {
            inline .fixed_little, .fixed_big => |Type| Type,
            .uleb128 => usize
        };

        comptime {
            if (@typeInfo(Tag) != .@"enum")
                @compileError("Tag type must be an enum, not " ++ @typeName(Tag));
            if (@typeInfo(HeaderInt) != .int)
                @compileError("Encoding type must have an underlying integer type, not " ++ @typeName(HeaderInt));
            if (@typeInfo(@typeInfo(Tag).@"enum".tag_type).int.bits < @typeInfo(HeaderInt).int.bits)
                @compileError("Underlying encoding integer has a larger bitwidth than tag type " ++ @typeName(Tag));

            // reader.skipBytes() takes a max 64 bits length
            if (@typeInfo(HeaderInt).int.bits > 64)
                @compileError(std.fmt.comptimePrint("Underlying encoding integer must not be greater than 64 bits (< {})", .{ @typeInfo(HeaderInt).int.bits }));

            // lacking uleb128 support
            if (@typeInfo(HeaderInt).int.signedness != .unsigned)
                @compileError("Underlying encoding integer may not be signed");
        }

        pub const Message = struct {

            tag: Tag,
            length: HeaderInt,
            value: []const u8,

            pub fn deinit(self: *const Message, allocator: std.mem.Allocator) void {
                // first expand the value to use its entire capacity before
                // attempting to deallocate it
                var buffer = self.value;
                buffer.len = self.length;
                allocator.free(buffer);
            }

            /// If the read length matches the payload's given length, taking
            /// into account if there was an EOF before reading ended. If
            /// false, the stream ended before this message could be completely
            /// read.
            pub fn is_complete(self: *const Message) bool {
                return self.length == self.value.len;
            }
        };

        pub const Tag = TagType;
        pub const encoding = encodingType;

        /// Max size is 4096 and exhaustive tags are disabled by default; use
        /// `read_options` to change it.
        pub fn read(allocator: std.mem.Allocator, reader: anytype) !Message {
            return read_options(allocator, reader, .{});
        }

        pub fn read_options(allocator: std.mem.Allocator, reader: anytype, options: ReadOptions) !Message {
            const tag = try read_head(reader);
            const is_invalid = std.enums.tagName(Tag, @enumFromInt(tag)) == null;
            if (is_invalid and options.exhaustive_tags and !options.discard) return error.InvalidTag;

            const length = try read_head(reader);

            if (is_invalid and options.exhaustive_tags)
                return try skip_and_error(error.InvalidTag, length, reader);
            if (length > options.max_size)
                return try skip_and_error(error.PayloadTooLarge, length, reader);

            var buffer = try allocator.alloc(u8, length);
            errdefer allocator.free(buffer);
            var write_buffer = buffer;
            var write_len: usize = 0;

            while (write_buffer.len != 0) {
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
                .fixed_big => try reader.readInt(HeaderInt, .big),
                .uleb128 => try uleb128.read(HeaderInt, reader)
            };
        }

        fn skip_and_error(comptime ret: anyerror, length: usize, reader: anytype) !noreturn {
            reader.skipBytes(length, .{}) catch |err| switch (err) {
                // normally no EndOfStream is given after the header was
                // parsed, only an incomplete buffer, so it makes sense to
                // discard the error and return PayloadTooLarge.
                error.EndOfStream => return ret
            };
            return ret;
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
                },
                .uleb128 => try uleb128.write(T, integer, writer)
            }
        }
    };
}

// Tests

const TestTag32 = enum(u32) {
    one = 0,
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

const TestTag16 = enum(u16) {
    one = 0,
    two,
    three,
    _
};

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

    const other_message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    defer other_message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag16.three, other_message.tag);
    try std.testing.expectEqual(@as(u32, 4), other_message.length);
    try std.testing.expectEqual(@as(usize, 4), other_message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, other_message.value);
    try std.testing.expect(other_message.is_complete());
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

test "read end of stream" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x01, 0x00,
        0x08 });
    const TlvInstance = Tlv(TestTag16, .{ .fixed_little = u16 });
    try std.testing.expectError(error.EndOfStream, TlvInstance.read(std.testing.allocator, test_buffer.reader()));
}

test "read exhaustive_tags" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x01, 0x00,
        0x04, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xEA, 0x00,
        0x01, 0x00,
        0x04, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF });
    const TlvInstance = Tlv(TestTag16, .{ .fixed_little = u16 });
    const options = ReadOptions { .exhaustive_tags = true };
    const message = try TlvInstance.read_options(std.testing.allocator, test_buffer.reader(), options);
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag16.two, message.tag);
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqual(@as(usize, 4), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, message.value);
    try std.testing.expect(message.is_complete());

    try std.testing.expectError(error.InvalidTag, TlvInstance.read_options(std.testing.allocator, test_buffer.reader(), options));

    const other_message = try TlvInstance.read_options(std.testing.allocator, test_buffer.reader(), options);
    defer other_message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag16.two, other_message.tag);
}

test "read exhaustive_tags + discard" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x01, 0x00,
        0x04, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xEA, 0x00,
        0x04, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF,
        0x02, 0x00,
        0x00, 0x00 });
    const TlvInstance = Tlv(TestTag16, .{ .fixed_little = u16 });
    const options = ReadOptions { .exhaustive_tags = true, .discard = true };
    const message = try TlvInstance.read_options(std.testing.allocator, test_buffer.reader(), options);
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag16.two, message.tag);
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqual(@as(usize, 4), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, message.value);
    try std.testing.expect(message.is_complete());

    try std.testing.expectError(error.InvalidTag, TlvInstance.read_options(std.testing.allocator, test_buffer.reader(), options));

    const other_message = try TlvInstance.read_options(std.testing.allocator, test_buffer.reader(), options);
    defer other_message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag16.three, other_message.tag);
}

test "read max_size" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x01, 0x00,
        0x08, 0x00,
        0xEA, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA,
        0x02, 0x00,
        0x04, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF });
    const TlvInstance = Tlv(TestTag16, .{ .fixed_little = u16 });
    try std.testing.expectError(error.PayloadTooLarge, TlvInstance.read_options(std.testing.allocator, test_buffer.reader(), .{ .max_size = 4 }));

    const message = try TlvInstance.read_options(std.testing.allocator, test_buffer.reader(), .{ .max_size = 4 });
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(TestTag16.three, message.tag);
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqual(@as(usize, 4), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, message.value);
    try std.testing.expect(message.is_complete());
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

    var outgoing = std.ArrayList(u8).init(std.testing.allocator);
    defer outgoing.deinit();
    try TlvInstance.write(.chroot, "/foo", outgoing.writer());

    try std.testing.expectEqualSlices(u8, &.{
        0x02, 0x00, 0x00, 0x00, // tag: chroot (2)
        0x04, 0x00, 0x00, 0x00, // length: 4
        '/', 'f', 'o', 'o'      // value: /foo
    }, outgoing.items);

    var incoming = std.io.fixedBufferStream(outgoing.items);
    const message = try TlvInstance.read(std.testing.allocator, incoming.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(Tag.chroot, message.tag);
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqualSlices(u8, "/foo", message.value);
    try std.testing.expect(message.is_complete());
}

const TestTag64 = enum(usize) { _ };

test "read uleb128" {
    var test_buffer = std.io.fixedBufferStream(&[_]u8 {
        0x81, 0x01,
        0x04,
        0x01, 0x02, 0x03, 0x04, 0xEA });
    const TlvInstance = Tlv(TestTag64, .uleb128);
    const message = try TlvInstance.read(std.testing.allocator, test_buffer.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 129), @intFromEnum(message.tag));
    try std.testing.expectEqual(@as(u32, 4), message.length);
    try std.testing.expectEqual(@as(usize, 4), message.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, message.value);
    try std.testing.expect(message.is_complete());
}

test "write uleb128" {
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();
    const TlvInstance = Tlv(TestTag64, .uleb128);
    try TlvInstance.write(@enumFromInt(129), "Hello world!", output.writer());

    try std.testing.expectEqualSlices(u8, &.{
        0x81, 0x01, // 129
        0x0C, // "Hello world!".len
        'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'
    }, output.items);
}

test "read/write uleb128 roundtrip" {
    const Tag = enum(usize) { _ };

    const TlvInstance = Tlv(Tag, .uleb128);

    var outgoing = std.ArrayList(u8).init(std.testing.allocator);
    defer outgoing.deinit();
    try TlvInstance.write(@enumFromInt(624485), "Hello world!", outgoing.writer());

    try std.testing.expectEqualSlices(u8, &.{
        0xE5, 0x8E, 0x26, // tag: 624485
        0x0C, // length: 12
        'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!' // value: Hello world!
    }, outgoing.items);

    var incoming = std.io.fixedBufferStream(outgoing.items);
    const message = try TlvInstance.read(std.testing.allocator, incoming.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(Tag, @enumFromInt(624485)), message.tag);
    try std.testing.expectEqual(@as(u32, 12), message.length);
    try std.testing.expectEqualSlices(u8, "Hello world!", message.value);
    try std.testing.expect(message.is_complete());
}

test "read/write uleb128 zero" {
    const Tag = enum(usize) { _ };

    const TlvInstance = Tlv(Tag, .uleb128);

    var outgoing = std.ArrayList(u8).init(std.testing.allocator);
    defer outgoing.deinit();
    try TlvInstance.write(@enumFromInt(0), "", outgoing.writer());

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, outgoing.items);

    var incoming = std.io.fixedBufferStream(outgoing.items);
    const message = try TlvInstance.read(std.testing.allocator, incoming.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(Tag, @enumFromInt(0)), message.tag);
    try std.testing.expectEqual(@as(u32, 0), message.length);
    try std.testing.expectEqualSlices(u8, "", message.value);
    try std.testing.expect(message.is_complete());
}

test "read/write uleb128 zero 2" {
    const Tag = enum(usize) { _ };

    const TlvInstance = Tlv(Tag, .uleb128);

    var outgoing = std.ArrayList(u8).init(std.testing.allocator);
    defer outgoing.deinit();
    try TlvInstance.write(@enumFromInt(0), "", outgoing.writer());
    try TlvInstance.write(@enumFromInt(1), "", outgoing.writer());

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x01, 0x00 }, outgoing.items);

    var incoming = std.io.fixedBufferStream(outgoing.items);
    const message = try TlvInstance.read(std.testing.allocator, incoming.reader());
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(Tag, @enumFromInt(0)), message.tag);
    try std.testing.expectEqual(@as(u32, 0), message.length);
    try std.testing.expectEqualSlices(u8, "", message.value);
    try std.testing.expect(message.is_complete());

    const other_message = try TlvInstance.read(std.testing.allocator, incoming.reader());
    defer other_message.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(Tag, @enumFromInt(1)), other_message.tag);
    try std.testing.expectEqual(@as(u32, 0), other_message.length);
    try std.testing.expectEqualSlices(u8, "", other_message.value);
    try std.testing.expect(other_message.is_complete());
}
