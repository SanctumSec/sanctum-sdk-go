/*
 * Stub for sanctum_vault_use_credential.
 *
 * The prebuilt libsanctum_ffi does not yet export this symbol (added in v0.4.0).
 * This weak stub satisfies the linker so existing tests can run. It returns
 * NOT_FOUND (-5) for any call. Remove this file once libsanctum_ffi is rebuilt
 * with use_credential support.
 */
#include "sanctum.h"

__attribute__((weak))
SanctumResult sanctum_vault_use_credential(struct SanctumVault *vault,
                                            const char *name,
                                            const char *agent_id,
                                            const char *operation,
                                            const char *params_json,
                                            uint8_t *out_json,
                                            uintptr_t *out_len) {
    (void)vault;
    (void)name;
    (void)agent_id;
    (void)operation;
    (void)params_json;
    (void)out_json;
    (void)out_len;
    return NOT_FOUND;
}
