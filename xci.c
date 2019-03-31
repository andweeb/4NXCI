#include <string.h>
#include "nsp.h"
#include "xci.h"
#include "rsa.h"

void xci_process(xci_ctx_t *ctx) {
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&ctx->header, 1, 0x200, ctx->file) != 0x200) {
        fprintf(stderr, "Failed to read XCI header!\n");
        return;
    }
    
    if (ctx->header.magic != MAGIC_HEAD) {
        fprintf(stderr, "Error: XCI header is corrupt!\n");
        exit(EXIT_FAILURE);
    }

    ctx->hfs0_hash_validity = check_memory_hash_table(ctx->file, ctx->header.hfs0_header_hash, ctx->header.hfs0_offset, ctx->header.hfs0_header_size, ctx->header.hfs0_header_size, 0);
    if (ctx->hfs0_hash_validity != VALIDITY_VALID) {
        fprintf(stderr, "Error: XCI partition is corrupt!\n");
        exit(EXIT_FAILURE);
    }
    
    nxci_ctx_t blank_ctx;
    memset(&blank_ctx, 0, sizeof(blank_ctx));
    
    ctx->partition_ctx.file = ctx->file;
    ctx->partition_ctx.offset = ctx->header.hfs0_offset;
    ctx->partition_ctx.tool_ctx = &blank_ctx;
    ctx->partition_ctx.name = "rootpt";
    hfs0_process(&ctx->partition_ctx);
    
    if (ctx->partition_ctx.header->num_files > 4) {
        fprintf(stderr, "Error: Invalid XCI partition!\n");
        exit(EXIT_FAILURE);    
    }
    
    for (unsigned int i = 0; i < ctx->partition_ctx.header->num_files; i++)  {
        hfs0_ctx_t *cur_ctx = NULL;
        
        hfs0_file_entry_t *cur_file = hfs0_get_file_entry(ctx->partition_ctx.header, i);
        char *cur_name = hfs0_get_file_name(ctx->partition_ctx.header, i);
        if (!strcmp(cur_name, "update") && ctx->update_ctx.file == NULL) {
            cur_ctx = &ctx->update_ctx;
        } else if (!strcmp(cur_name, "normal") && ctx->normal_ctx.file == NULL) {
            cur_ctx = &ctx->normal_ctx;
        } else if (!strcmp(cur_name, "secure") && ctx->secure_ctx.file == NULL) {
            cur_ctx = &ctx->secure_ctx;
        } else if (!strcmp(cur_name, "logo") && ctx->logo_ctx.file == NULL) {
            cur_ctx = &ctx->logo_ctx;
        } 
        
        if (cur_ctx == NULL) {
            fprintf(stderr, "Unknown XCI partition: %s\n", cur_name);
            exit(EXIT_FAILURE);
        }
        
        cur_ctx->name = cur_name;
        cur_ctx->offset = ctx->partition_ctx.offset + hfs0_get_header_size(ctx->partition_ctx.header) + cur_file->offset;
        cur_ctx->tool_ctx = ctx->tool_ctx;
        cur_ctx->file = ctx->file;
        hfs0_process(cur_ctx);
    }
    
    for (unsigned int i = 0; i < 0x10; i++) {
        ctx->iv[i] = ctx->header.reversed_iv[0xF-i];
    }
    xci_save(ctx);

}

void xci_save(xci_ctx_t *ctx) {
    /* Save Secure Partition. */
	printf("Saving Secure Partition...\n");
	os_makedir(ctx->tool_ctx->settings.secure_dir_path.os_path);
	for (uint32_t i = 0; i < ctx->secure_ctx.header->num_files; i++) {
		hfs0_save_file(&ctx->secure_ctx, i, &ctx->tool_ctx->settings.secure_dir_path);
	}
	printf("\n");
}
