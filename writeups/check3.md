Checkpoint 3 Writeup
====================

My name: [fill in]
My SUNet ID: [fill in, if applicable]
I collaborated with: [fill in]
This checkpoint took me about [fill in] hours.

Program Structure and Design
----------------------------

TCPSender tracks the first unacknowledged absolute sequence number and
the first unsent absolute sequence number. The receiver's advertised
window gives the right edge for push(). A zero-size window is treated
as one only while deciding whether push() can send a probe.

Each new segment is as large as the remaining window and payload limit
allow. SYN and FIN each consume one sequence number. Segments that
consume sequence numbers are retained in a deque with their absolute
end positions. A segment stays outstanding until an ACK passes its end,
even if the ACK partially covers it. The in-flight counter follows
this full-segment convention.

One timer protects the oldest outstanding segment. New segments do not
restart it. A new valid ACK resets the RTO and retransmission count,
and restarts the timer if any segment remains outstanding. A timeout
resends the oldest segment. The RTO doubles and the retry count rises
only when the receiver advertises a nonzero window.

Implementation Challenges
-------------------------

The key distinction was between ACK advancement and complete segment
acknowledgment. A partial ACK moves the window's left edge but leaves
the original segment in the retransmission queue. This also matters
when a FIN is waiting for one more sequence number of window space.
The timer uses only tick() input and preserves the oldest segment's
deadline when later segments are sent.

Remaining Bugs
--------------

None known after check3 passed all 36 tests using clang++ on UTM.
A separate partial-ACK check also verified full-segment accounting
and retransmission of the original segment.
