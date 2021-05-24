#include "string.h"

#include "get_merkle_leaf_index.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../common/merkle.h"
#include "../../crypto.h"
#include "../../constants.h"
#include "../client_commands.h"


static void process_response(dispatcher_context_t *dc);


void flow_get_merkle_leaf_index(dispatcher_context_t *dc) {
    get_merkle_leaf_index_state_t *state = (get_merkle_leaf_index_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t request[1 + 20 + 20];
    request[0] = CCMD_GET_MERKLE_LEAF_INDEX;
    memcpy(request + 1, state->root, 20);
    memcpy(request + 1 + 20, state->leaf_hash, 20);

    dc->send_response(request, sizeof(request), SW_INTERRUPTED_EXECUTION);
    dc->next(process_response);
}


static void process_response(dispatcher_context_t *dc) {
    get_merkle_leaf_index_state_t *state = (get_merkle_leaf_index_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t found;
    uint64_t index;

    if (!buffer_read_u8(&dc->read_buffer, &found) || !buffer_read_varint(&dc->read_buffer, &index)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (found != 0 && found != 1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    // set results
    state->found = found;
    state->index = (uint32_t)index;

    if (found) {
        // We ask the host for the leaf hash with that index
        call_get_merkle_leaf_hash(dc,
                                  state->root,
                                  state->size,
                                  index,
                                  state->returned_merkle_leaf_hash);

        if (memcmp(state->leaf_hash, state->returned_merkle_leaf_hash, 20) != 0){
            dc->send_sw(SW_INCORRECT_DATA);
        }
    }
}