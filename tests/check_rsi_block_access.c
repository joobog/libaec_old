#include "check_aec.h"
/*#include "../src/vector.h"*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

/*#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"*/
/*#define BYTE_TO_BINARY(byte)  \*/
/*  (byte & 0x80 ? '1' : '0'), \*/
/*  (byte & 0x40 ? '1' : '0'), \*/
/*  (byte & 0x20 ? '1' : '0'), \*/
/*  (byte & 0x10 ? '1' : '0'), \*/
/*  (byte & 0x08 ? '1' : '0'), \*/
/*  (byte & 0x04 ? '1' : '0'), \*/
/*  (byte & 0x02 ? '1' : '0'), \*/
/*  (byte & 0x01 ? '1' : '0') */

static const char* aec_get_error_message(int code)
{
    if (code == AEC_MEM_ERROR) return "AEC_MEM_ERROR";
    if (code == AEC_DATA_ERROR) return "AEC_DATA_ERROR";
    if (code == AEC_STREAM_ERROR) return "AEC_STREAM_ERROR";
    if (code == AEC_CONF_ERROR) return "AEC_CONF_ERROR";
    if (code == AEC_OK) return "AEC_OK";
    /*if (code == AEC_NOT_IMPLEMENTED) return "AEC_NOT_IMPLEMENTED";*/
    return "Unknown error code";
}

static void print_aec_stream_info(struct aec_stream* strm, const char* func)
{
    fprintf(stderr, "%s() aec_stream.flags=%u\n",           func, strm->flags);
    fprintf(stderr, "%s() aec_stream.rsi=%u\n",             func, strm->rsi);
    fprintf(stderr, "%s() aec_stream.block_size=%u\n",      func, strm->block_size);
    fprintf(stderr, "%s() aec_stream.bits_per_sample=%u\n", func, strm->bits_per_sample);
    fprintf(stderr, "%s() aec_stream.avail_in=%lu\n",       func, strm->avail_in);
    fprintf(stderr, "%s() aec_stream.avail_out=%lu\n",      func, strm->avail_out);
    fprintf(stderr, "%s() aec_stream.total_out=%lu\n",      func, strm->total_out);
}

struct aec_context {
    size_t nvalues;
    int flags;
    int rsi;
    int block_size;
    int bits_per_sample;
    int bytes_per_sample;
    unsigned char * obuf;
    unsigned char * ebuf;
    unsigned char * dbuf;
    size_t obuf_len;
    size_t ebuf_len;
    size_t dbuf_len;
    size_t ebuf_total;
};

static int get_input_bytes(struct aec_context *ctx) {
    if (ctx->flags & AEC_DATA_3BYTE) {
        printf("AES_DATA_3BYTE is not supported\n");
        exit(1);
    }
    if (ctx->bits_per_sample < 1 || ctx->bits_per_sample > 32) {
        fprintf(stderr, "Invalid bits_per_sample: %d\n", ctx->bits_per_sample);
        exit(1);
    }
    int nbytes =  (ctx->bits_per_sample + 7) / 8;
    if (nbytes == 3) nbytes = 4;
    return nbytes;
}

typedef void (*data_generator_t)(struct aec_context *ctx);

static void data_generator_zero(struct aec_context *ctx)
{
    size_t nbytes = ctx->bytes_per_sample;
    if (ctx->obuf_len % nbytes) {
        fprintf(stderr, "Invalid buffer_size: %lu\n", ctx->obuf_len);
        exit(1);
    }

    size_t nvalues = ctx->obuf_len / nbytes;
    /*size_t max_value = 1 << (ctx->bits_per_sample - 1);*/

    for (size_t i = 0; i < nvalues; i++) {
        size_t value = 0;
        unsigned char *value_p = (unsigned char*) &value;
        for (size_t j = 0; j < nbytes; j++) {
            if (ctx->flags & AEC_DATA_MSB) {
                ctx->obuf[i * nbytes + j] = value_p[nbytes - j - 1];
            }
            else {
                ctx->obuf[i * nbytes + j] = value_p[j];
            }
        }
    }
}


static void data_generator_random(struct aec_context *ctx)
{
    size_t nbytes = ctx->bytes_per_sample;
    if (ctx->obuf_len % nbytes) {
        fprintf(stderr, "Invalid buffer_size: %lu\n", ctx->obuf_len);
        exit(1);
    }

    size_t nvalues = ctx->obuf_len / nbytes;
    /*size_t mask = 0xFFFFFFFF >> (sizeof(mask) * 8 - ctx->bits_per_sample);*/
    size_t mask = (1 << (ctx->bits_per_sample - 1))-1;

    for (size_t i = 0; i < nvalues; i++) {
        size_t value = rand() & mask;
        unsigned char *value_p = (unsigned char*) &value;

        for (size_t j = 0; j < nbytes; j++) {
            if (ctx->flags & AEC_DATA_MSB) {
                ctx->obuf[i * nbytes + j] = value_p[nbytes - j - 1];
            }
            else {
                ctx->obuf[i * nbytes + j] = value_p[j];
            }
        }
    }
}


static void data_generator_incr(struct aec_context *ctx)
{
    size_t nbytes = ctx->bytes_per_sample;
    if (ctx->obuf_len % nbytes) {
        fprintf(stderr, "Invalid buffer_size: %lu\n", ctx->obuf_len);
        exit(1);
    }

    size_t nvalues = ctx->obuf_len / nbytes;
    size_t max_value = 1 << (ctx->bits_per_sample - 1);

    for (size_t i = 0; i < nvalues; i++) {
        size_t value = i % max_value;
        unsigned char *value_p = (unsigned char*) &value;
        for (size_t j = 0; j < nbytes; j++) {
            if (ctx->flags & AEC_DATA_MSB) {
                ctx->obuf[i * nbytes + j] = value_p[nbytes - j - 1];
            }
            else {
                ctx->obuf[i * nbytes + j] = value_p[j];
            }
        }
    }
}


static void ctx_init(struct aec_context *ctx)
{
    ctx->nvalues = 0;
    ctx->flags = 0;
    ctx->rsi = 0;
    ctx->block_size = 0;
    ctx->bits_per_sample = 0;
    ctx->obuf = NULL;
    ctx->ebuf = NULL;
    ctx->dbuf = NULL;
    ctx->obuf_len = 0;
    ctx->ebuf_len = 0;
    ctx->dbuf_len = 0;
    ctx->ebuf_total = 0;
}


#define PREPARE_ENCODE(strm_e, ctx, flags) \
{ \
    (strm_e)->flags = flags; \
    (strm_e)->rsi = (ctx)->rsi; \
    (strm_e)->block_size = (ctx)->block_size; \
    (strm_e)->bits_per_sample = (ctx)->bits_per_sample; \
    (strm_e)->next_in = (ctx)->obuf; \
    (strm_e)->avail_in = (ctx)->obuf_len; \
    (strm_e)->next_out = (ctx)->ebuf; \
    (strm_e)->avail_out = (ctx)->ebuf_len; \
    int status = 0; \
    if ((status = aec_buffer_encode((strm_e))) != 0) { \
        /*printf("ERROR: Encoding: Encoding without offsets failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return status; \
    } \
    (ctx)->ebuf_total = (strm_e)->total_out; \
    \
    struct aec_stream strm_d; \
    strm_d = (*strm_e); \
    strm_d.next_in = (ctx)->ebuf; \
    strm_d.avail_in = (ctx)->ebuf_total; \
    strm_d.next_out = (ctx)->dbuf; \
    strm_d.avail_out = (ctx)->dbuf_len; \
    if ((status = aec_buffer_decode((&strm_d))) != 0) { \
        /*printf("ERROR: Decoding: Decoding without offsets failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return status; \
    } \
}


#define PREPARE_ENCODE_WITH_OFFSETS(strm_eo, ctx, flags, offsets_ptr, offsets_count_ptr) \
{ \
    (strm_eo)->flags = flags; \
    (strm_eo)->rsi = (ctx)->rsi; \
    (strm_eo)->block_size = (ctx)->block_size; \
    (strm_eo)->bits_per_sample = (ctx)->bits_per_sample; \
    (strm_eo)->next_in = (ctx)->obuf; \
    (strm_eo)->avail_in = (ctx)->obuf_len; \
    (strm_eo)->next_out = (ctx)->ebuf; \
    (strm_eo)->avail_out = (ctx)->ebuf_len; \
    int status = 0; \
    if ((status = aec_encode_init((strm_eo))) != AEC_OK) { \
        /*printf("ERROR: Encoding: Encoding with offsets failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return(status); \
    } \
    aec_encode_enable_offsets((strm_eo)); \
    if ((status = aec_encode((strm_eo), AEC_FLUSH)) != 0) { \
        /*printf("ERROR: Encoding: Enable offsets failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return(status); \
    } \
    aec_encode_count_offsets((strm_eo), (offsets_count_ptr)); \
    (offsets_ptr) = (size_t*) malloc(sizeof(*(offsets_ptr)) * *(offsets_count_ptr)); \
    if ((status = aec_encode_get_offsets((strm_eo), (offsets_ptr), *(offsets_count_ptr)))) { \
        /*printf("ERROR: Encoding: Get offsets failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return(status); \
    } \
    aec_encode_end((strm_eo)); \
    ctx->ebuf_total = (strm_eo)->total_out; \
}


#define PREPARE_DECODE_WITH_OFFSETS(strm_do, ctx, flags, offsets_ptr, offsets_count_ptr) \
{ \
    (strm_do)->flags = (ctx)->flags; \
    (strm_do)->rsi = (ctx)->rsi; \
    (strm_do)->block_size = (ctx)->block_size; \
    (strm_do)->bits_per_sample = (ctx)->bits_per_sample; \
    (strm_do)->next_in = (ctx)->ebuf; \
    (strm_do)->avail_in = (ctx)->ebuf_total; \
    (strm_do)->next_out = (ctx)->dbuf; \
    (strm_do)->avail_out = (ctx)->dbuf_len; \
    if ((status = aec_decode_init((strm_do))) != AEC_OK) { \
        /*printf("ERROR: Decoding init failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return status; \
    } \
    if ((status = aec_decode_enable_offsets((strm_do))) != AEC_OK) { \
        /*printf("ERROR: Decoding: Enable offsets failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return status; \
    }; \
    if ((status = aec_decode((strm_do), AEC_FLUSH)) != AEC_OK) { \
        /*printf("ERROR: Decoding failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return status; \
    } \
    if ((status = aec_decode_count_offsets((strm_do), (offsets_count_ptr))) != AEC_OK) { \
        /*printf("ERROR: Decoding: Count offsets failed  (%d) %s\n", status, aec_get_error_message(status)); */ \
        return status; \
    } \
    (offsets_ptr) = (size_t*) malloc(sizeof(*(offsets_ptr)) * *(offsets_count_ptr)); \
    if ((status = aec_decode_get_offsets((strm_do), (offsets_ptr), *(offsets_count_ptr))) != AEC_OK) { \
        /*printf("ERROR: Decoding: Get offsets failed (%d) %s\n", status, aec_get_error_message(status)); */ \
        return status; \
    }; \
    for (size_t i = 0; i < (strm_do)->total_out; ++i) { \
        assert((ctx)->dbuf[i] == (ctx)->obuf[i]); \
    } \
    aec_decode_end((strm_do)); \
}


static int test_at(struct aec_context *ctx) 
{
    int status = AEC_OK;
    int flags = ctx->flags;
    unsigned short *obuf = (unsigned short*) ctx->obuf;

    struct aec_stream strm_encode;
    PREPARE_ENCODE(&strm_encode, ctx, flags);

    struct aec_stream strm_decode;
    size_t *offsets;
    size_t offsets_count;
    PREPARE_DECODE_WITH_OFFSETS(&strm_decode, ctx, flags, offsets, &offsets_count);

    size_t rsi_len = ctx->rsi * ctx->block_size * ctx->bytes_per_sample;
    unsigned char *rsi_buf = malloc(rsi_len);
    if (rsi_buf == NULL) {
        printf("ERROR: Failed to allocate rsi buffer\n");
        exit(1);
    }

    for (int i = 0; i < offsets_count; ++i) {
        struct aec_stream strm_at;
        strm_at.flags = flags;
        strm_at.rsi = ctx->rsi;
        strm_at.block_size = ctx->block_size;
        strm_at.bits_per_sample = ctx->bits_per_sample;
        strm_at.next_in = ctx->ebuf;
        strm_at.avail_in = ctx->ebuf_total;
        strm_at.next_out = rsi_buf;
        strm_at.avail_out = ctx->dbuf_len - i * rsi_len > rsi_len ? rsi_len : ctx->dbuf_len % rsi_len;

        if ((status = aec_rsi_at(&strm_at, offsets, offsets_count, i)) != AEC_OK) {
            printf("Error: %s\n", aec_get_error_message(status));
            break;
        }
        for (int j = 0; j < strm_at.total_out; j++) {
            if (j == ctx->rsi * ctx->block_size * ctx->bytes_per_sample + j > ctx->obuf_len) {
                break;
            }
            assert(rsi_buf[j] == ctx->obuf[i * ctx->block_size * ctx->rsi * ctx->bytes_per_sample + j]);
        }
    }

    free(offsets);
    free(rsi_buf);
    return status;
}


int test_read(struct aec_context *ctx) 
{
    int status = AEC_OK;
    int flags = ctx->flags;

    struct aec_stream strm_encode;
    PREPARE_ENCODE(&strm_encode, ctx, flags);

    struct aec_stream strm_decode;
    size_t *offsets = NULL;
    size_t offsets_size = 0;
    PREPARE_DECODE_WITH_OFFSETS(&strm_decode, ctx, flags, offsets, &offsets_size);

    size_t rsi_len = ctx->rsi * ctx->block_size * ctx->bytes_per_sample;
    unsigned char *rsi_buf = malloc(rsi_len);
    unsigned rsi_n = ctx->obuf_len / (ctx->rsi * ctx->block_size); // Number of full rsi blocks
    unsigned rsi_r = ctx->obuf_len % (ctx->rsi * ctx->block_size); // Remainder
  
    // Edge case: Imposible to get wanted number of slices
    size_t wanted_num_slices = 3;
    if (wanted_num_slices > ctx->obuf_len) {
        wanted_num_slices = ctx->obuf_len;
    }

    // Optimize the size of the last slice
    // Make sure that the last slice is not too small
    size_t slice_size = (ctx->obuf_len % ((ctx->obuf_len / wanted_num_slices) * wanted_num_slices)) == 0 ? ctx->obuf_len / wanted_num_slices : ctx->obuf_len / wanted_num_slices + 1;

    size_t num_slices = ctx->obuf_len / slice_size;
    size_t remainder = ctx->obuf_len % slice_size;

    size_t slice_offsets[num_slices + 1];
    size_t slice_sizes[num_slices + 1];

    for (size_t i = 0; i < num_slices; ++i) {
        slice_offsets[i] = slice_size * i;
        slice_sizes[i] = slice_size;
    }
    if (remainder > 0) {
        slice_offsets[num_slices] = slice_size * (num_slices - 1);
        slice_sizes[num_slices] = remainder;
        ++num_slices;
    }

    for (size_t i = 0; i < num_slices; ++i) {
        struct aec_stream strm_read;
        strm_read.flags = ctx->flags;
        strm_read.rsi = ctx->rsi;
        strm_read.block_size = ctx->block_size;
        strm_read.bits_per_sample = ctx->bits_per_sample;
        strm_read.avail_in = strm_encode.total_out;
        strm_read.next_in = ctx->ebuf; 
        strm_read.avail_out = ctx->dbuf_len;
        strm_read.next_out = ctx->dbuf;

        unsigned char *read_buf = malloc(slice_sizes[i]);
        if ((status = aec_read(&strm_read, offsets, offsets_size, read_buf, slice_sizes[i], slice_offsets[i])) != AEC_OK) {
            print_aec_stream_info(&strm_read, __func__);
            printf("ctx.bytes_per_sample=%d\n", ctx->bytes_per_sample);
            printf("Error: Failed reading chunk of data (%d)\n", status);
            return status;
        }
        for (size_t j = 0; j < slice_sizes[i]; ++j) {
            assert(ctx->obuf[slice_offsets[i] + j] == read_buf[j]);
        }
        free(read_buf);
    }

    free(offsets);
    free(rsi_buf);
    return status;
}


// Tests 
int test_offsets(struct aec_context *ctx) {
    int status = AEC_OK;
    int flags = ctx->flags;

    struct aec_stream strm1;
    size_t *encode_offsets_ptr;
    size_t encode_offsets_size;
    PREPARE_ENCODE_WITH_OFFSETS(&strm1, ctx, flags, encode_offsets_ptr, &encode_offsets_size);

    struct aec_stream strm2;
    size_t *decode_offsets_ptr;
    size_t decode_offsets_size;
    PREPARE_DECODE_WITH_OFFSETS(&strm2, ctx, flags, decode_offsets_ptr, &decode_offsets_size);
    size_t size = decode_offsets_size > 10 ? 10 : decode_offsets_size;

    for (size_t i = 0; i < encode_offsets_size; ++i) {
        if (encode_offsets_ptr[i] != decode_offsets_ptr[i]) {
            printf("Error: encode_offsets_ptr[%zu] = %zu, decode_offsets_ptr[%zu] = %zu\n", i, encode_offsets_ptr[i], i, decode_offsets_ptr[i]);
            assert(0);
        }
    }

    free(decode_offsets_ptr);
    free(encode_offsets_ptr);
    return status;
}


/*AEC_DATA_SIGNED 1*/
/*AEC_DATA_3BYTE 2*/
/*AEC_DATA_MSB 4*/
/*AEC_DATA_PREPROCESS 8*/
/*AEC_RESTRICTED 16*/
/*AEC_PAD_RSI 32*/
/*AEC_NOT_ENFORCE 64*/

int main(void)
{
    int status;
    size_t ns[] = {1, 255, 256, 255*10, 256*10, 67000};
    size_t rsis[] = {1, 2, 255, 256, 512, 1024, 4095, 4096};
    size_t bss[] = {8, 16, 32, 64};
    size_t bpss[] = {1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32};

    data_generator_t data_generators[] = {data_generator_zero, data_generator_random, data_generator_incr};

    for (size_t n_i = 0; n_i < sizeof(ns) / sizeof(ns[0]); ++n_i) {
        for (size_t rsi_i = 0; rsi_i < sizeof(rsis) / sizeof(rsis[0]); ++rsi_i) {
            for (size_t bs_i = 0; bs_i < sizeof(bss) / sizeof(bss[0]); ++bs_i) {
                for (size_t bps_i = 0; bps_i < sizeof(bpss) / sizeof(bpss[0]); ++bps_i) {
                    struct aec_context ctx;
                    ctx.nvalues = ns[n_i];
                    ctx.flags = AEC_DATA_PREPROCESS;
                    ctx.rsi = rsis[rsi_i];
                    ctx.block_size = bss[bs_i];
                    ctx.bits_per_sample = bpss[bps_i];
                    ctx.bytes_per_sample = get_input_bytes(&ctx);
                    size_t input_size = ctx.nvalues * ctx.bytes_per_sample;
                    ctx.obuf_len = input_size;
                    ctx.ebuf_len = input_size * 67 / 64 + 256;
                    ctx.dbuf_len = input_size;
                    ctx.obuf = calloc(1, ctx.obuf_len);
                    ctx.ebuf = calloc(1, ctx.ebuf_len);
                    ctx.dbuf = calloc(1, ctx.dbuf_len);
                    if (ctx.obuf == NULL || ctx.ebuf == NULL || ctx.dbuf == NULL) {
                        printf("Error: Failed allocating memory\n");
                        return 1;
                    }

                    for (size_t i = 0; i < sizeof(data_generators) / sizeof(data_generators[0]); ++i) {
                        data_generators[i](&ctx);
                        printf("Testing test_at()      ");
                        printf("nvalues=%zu, rsi=%zu, block_size=%zu, bits_per_sample=%zu ... ", ns[n_i], rsis[rsi_i], bss[bs_i], bpss[bps_i]);
                        status = test_at(&ctx);
                        if (status != AEC_OK) {
                            printf("%s\n", CHECK_FAIL);
                        }
                        else {
                            printf("%s\n", CHECK_PASS);
                        }
                        printf("Testing test_read()    ");
                        printf("nvalues=%zu, rsi=%zu, block_size=%zu, bits_per_sample=%zu ... ", ns[n_i], rsis[rsi_i], bss[bs_i], bpss[bps_i]);
                        status = test_read(&ctx);
                        if (status != AEC_OK) {
                            printf("%s\n", CHECK_FAIL);
                        }
                        else {
                            printf("%s\n", CHECK_PASS);
                        }
                        printf("Testing test_offsets() ");
                        printf("nvalues=%zu, rsi=%zu, block_size=%zu, bits_per_sample=%zu ... ", ns[n_i], rsis[rsi_i], bss[bs_i], bpss[bps_i]);
                        status = test_offsets(&ctx);
                        if (status != AEC_OK) {
                            printf("%s\n", CHECK_FAIL);
                        }
                        else {
                            printf("%s\n", CHECK_PASS);
                        }
                    }
                    free(ctx.obuf);
                    free(ctx.ebuf);
                    free(ctx.dbuf);
                }
            }
        }
    }
    return status;
}
