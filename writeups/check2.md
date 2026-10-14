Checkpoint 2 Writeup
====================

My name: [fill in]
My SUNet ID: [fill in, if applicable]
I collaborated with: [fill in]
This lab took me about [fill in] hours.

Program Structure and Design
----------------------------

Wrap32::wrap adds the low 32 bits of an absolute sequence number to the ISN.
Wrap32::unwrap starts with the smallest nonnegative absolute candidate, then
adds whole 2^32 cycles to reach the candidate at or below the checkpoint.
It compares this candidate with the next cycle, checking for uint64 overflow.
The lower candidate wins a tie. This avoids converting a large checkpoint
to a signed integer.

TCPReceiver stores the ISN in an optional field set only by the first SYN.
Segments arriving before SYN have no stream position and are ignored.
receive() unwraps the segment's sequence number near the first unassembled
byte. It accounts for SYN's sequence number before giving the payload and
FIN flag to Reassembler. The Reassembler handles overlap, gaps, and EOF.

send() computes ACK from SYN, bytes already pushed, and FIN only after EOF
has been assembled. It caps the advertised ByteStream capacity at 65,535.
An incoming RST sets the stream error; the outgoing RST reports that error.

Implementation Challenges
-------------------------

The main indexing pitfall was that SYN uses one sequence number but no stream
index. A segment with SYN and data starts its payload at stream index zero.
FIN must advance ACK only after the Reassembler closes the stream.
The previous signed-offset unwrap draft could not represent checkpoints
above INT64_MAX, so I replaced it with unsigned cycle candidates.

Remaining Bugs
--------------

None known after check2 passed all 29 tests using clang++ on the UTM VM.
The GCC sanitizer version of wrapping_integers_roundtrip exceeded the
provided 12-second timeout; the clang++ sanitizer run passed.
