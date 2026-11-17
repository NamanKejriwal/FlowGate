package com.packetanalyzer.types;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FiveTupleTest {

    @Test
    void flow_hash_is_the_same_in_both_directions() {
        FiveTuple request = new FiveTuple(0x6401A8C0, 0x0F0F0F0F, 10001, 80, 6);
        FiveTuple reply   = request.reverse();

        assertEquals(request.flowHash(), reply.flowHash());
    }

    @Test
    void plain_hash_and_equals_stay_direction_specific() {
        // Each direction is still its own key in the connection table
        FiveTuple request = new FiveTuple(0x6401A8C0, 0x0F0F0F0F, 10001, 80, 6);
        FiveTuple reply   = request.reverse();

        assertNotEquals(request, reply);
        assertEquals(request, new FiveTuple(0x6401A8C0, 0x0F0F0F0F, 10001, 80, 6));
    }
}
