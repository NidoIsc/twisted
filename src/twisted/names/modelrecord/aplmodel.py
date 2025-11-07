
# System imports
import socket
import struct

class AplItem:
    """
    Represents a single APL item class for IPv4 (family=1)
    """

    __slots__ = ("family", "negation", "address", "prefix")

    def __init__(self, family, negation, address, prefix):
        # Only IPv4 supported
        if family != 1:
            raise ValueError("Only IPv4 is supported (family=1)")

        # Keep family as provided
        self.family = family  # family == 1

        # Negation flag
        self.negation = bool(negation)

        # Validate prefix
        prefix = int(prefix)
        if not (0 <= prefix <= 32):
            raise ValueError("Prefix must be between 0 and 32")
        self.prefix = prefix

        # Convert address
        if isinstance(address, str):
            # Convert text IPv4 string → packed bytes
            self.address = socket.inet_aton(address)

        elif isinstance(address, bytes):
            # Already raw packed bytes (must be exactly 4 bytes for IPv4)
            if len(address) != 4:
                raise ValueError("IPv4 packed address must be 4 bytes")
            self.address = address

        else:
            raise TypeError(f"Invalid IPv4 address type: {type(address)}")


    def to_wire(self):
        # Truncate trailing zero octets
        addr_bytes = self.address
        last = 0
        for i in range(len(addr_bytes) - 1, -1, -1):
            if addr_bytes[i] != 0:
                last = i + 1
                break
        addr_bytes = addr_bytes[:last]

        # Length byte: top bit = negation, lower 7 bits = length
        length = len(addr_bytes)
        if self.negation:
            length |= 0x80
        # Pack family (2 bytes), prefix (1 byte), length (1 byte)
        header = struct.pack("!HBB", self.family, self.prefix, length)
        return header + addr_bytes

    @classmethod
    def from_wire(cls, wire, offset):
        # wire: bytes, offset: start index
        family, prefix, length = struct.unpack("!HBB", wire[offset:offset+4])
        negation = False
        if length & 0x80:
            negation = True
            length &= 0x7F
        offset += 4
        addr_bytes = wire[offset:offset+length]
        offset += length
        # pad to 4 bytes
        addr_bytes += b"\x00" * (4 - len(addr_bytes))
        address = socket.inet_ntoa(addr_bytes)
        return cls(family, negation, address, prefix), offset

    def __str__(self):
        prefix_str = f"{self.prefix}"
        return f"!{self.family}:{socket.inet_ntoa(self.address)}/{prefix_str}" if self.negation else f"{self.family}:{socket.inet_ntoa(self.address)}/{prefix_str}"
