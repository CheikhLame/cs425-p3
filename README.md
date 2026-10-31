# Project 3

- Name: Cheikh Lame
- Email: cheikhlame@u.boisestate.edu
- Class: CS425-001

## Known Bugs or Issues


No known issues as far as I can tell.

## Experience


While going through the assignment, I completed and tested each function as I went along. This approach helped in developing my understanding of the project, especially the longest prefix match section.

## Analysis

The subnet calculations use fixed-width bit operations, so masking, network
and broadcast address calculation, host counting, and containment checks all
run in constant time. Splitting a network takes time proportional to the
number of subnets printed. The forwarding table uses a linear scan: adding a
route checks existing entries for duplicates, and lookup checks each route
for a match, so both operations take O(R) time for R routes. Loading R routes
therefore takes O(R^2) time in the worst case and O(R) memory. This is
appropriate for the assignment's sample tables; a binary trie would be a
better fit for a large routing table.

The tests cover strict rejection of malformed addresses and routes, CIDR
boundary cases including /0, /31, and /32, subnet splitting, table loading,
and longest-prefix selection independent of insertion order. The latest
coverage report for `src/lab.c` shows 100% line and branch coverage, and all
six test cases pass. The only excluded branches are failures from allocation
and stream-status library calls.
