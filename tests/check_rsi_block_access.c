#include "check_aec.h"
#include "../src/vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

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

static int get_input_bytes(int bits_per_sample) {
    if (bits_per_sample < 1 || bits_per_sample > 32) {
        fprintf(stderr, "Invalid bits_per_sample: %d\n", bits_per_sample);
        exit(1);
    }
    int nbytes =  (bits_per_sample - 1) / 8 + 1;
    if (nbytes == 3) nbytes = 4;
    return nbytes;
}

struct aec_context {
    size_t nvalues;
    int flags;
    int rsi;
    int block_size;
    int bits_per_sample;
    unsigned char * obuf;
    unsigned char * ebuf;
    unsigned char * dbuf;
    size_t obuf_len;
    size_t ebuf_len;
    size_t dbuf_len;
    size_t ebuf_total;
};


/*static void data_generator_zero(struct aec_context *ctx) {*/
/*    size_t nbytes = get_input_bytes(ctx->bits_per_sample);*/
/*    if (ctx->obuf_len %= nbytes) {*/
/*        fprintf(stderr, "Invalid buffer_size: %lu\n", ctx->obuf_len);*/
/*        exit(1);*/
/*    }*/
/*    memset(ctx->obuf, 0, ctx->obuf_len);*/
/*}*/


static void data_generator_zero(struct aec_context *ctx) {
    size_t nbytes = get_input_bytes(ctx->bits_per_sample);
    if (ctx->obuf_len % nbytes) {
        fprintf(stderr, "Invalid buffer_size: %lu\n", ctx->obuf_len);
        exit(1);
    }

    size_t nvalues = ctx->obuf_len / nbytes;
    size_t max_value = 1 << (ctx->bits_per_sample - 1);
    assert(nvalues < max_value);

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



static void data_generator_random(struct aec_context *ctx) {
    size_t nbytes = get_input_bytes(ctx->bits_per_sample);
    if (ctx->obuf_len % nbytes) {
        fprintf(stderr, "Invalid buffer_size: %lu\n", ctx->obuf_len);
        exit(1);
    }

    size_t nvalues = ctx->obuf_len / nbytes;
    size_t mask = 0xFFFFFFFF >> (sizeof(mask) * 8 - ctx->bits_per_sample);

    for (size_t i = 0; i < nvalues; i++) {
        size_t value = rand() & mask;
        unsigned char *value_p = (unsigned char*) &value;
        printf("b: ");
        for (size_t j = 0; j < nbytes; j++) {
            if (ctx->flags & AEC_DATA_MSB) {
                ctx->obuf[i * nbytes + j] = value_p[nbytes - j - 1];
            }
            else {
                ctx->obuf[i * nbytes + j] = value_p[j];
            }
            printf("%02X ", ctx->obuf[i * nbytes + j]);
        }
        printf("\n");
    }
}


static void data_generator_incr(struct aec_context *ctx) {
    size_t nbytes = get_input_bytes(ctx->bits_per_sample);
    if (ctx->obuf_len % nbytes) {
        fprintf(stderr, "Invalid buffer_size: %lu\n", ctx->obuf_len);
        exit(1);
    }

    size_t nvalues = ctx->obuf_len / nbytes;
    size_t max_value = 1 << (ctx->bits_per_sample - 1);
    assert(nvalues < max_value);

    for (size_t i = 0; i < nvalues; i++) {
        size_t value = i;
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


static void ctx_init(struct aec_context *ctx) {
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
    /*ctx->offsets = NULL;*/
}


int encode(struct aec_context *ctx, struct aec_stream *strm) 
{
    printf("%s\n", __PRETTY_FUNCTION__);
    strm->next_in = ctx->obuf;
    strm->avail_in = ctx->obuf_len;
    strm->next_out = ctx->ebuf;
    strm->avail_out = ctx->ebuf_len;

    int err = 0;
    if ((err = aec_buffer_encode(strm)) != 0) {
        printf("ERROR: Encoding failed (%d) %s\n", err, aec_get_error_message(err));
        return(1);
    }

    return 0;
}


int decode(struct aec_context *ctx, struct aec_stream *strm, struct vector_t *offsets) 
{
    printf("%sX\n", __PRETTY_FUNCTION__);
    strm->next_in = ctx->ebuf;
    strm->avail_in = ctx->ebuf_len;
    strm->next_out = ctx->dbuf;
    strm->avail_out = ctx->dbuf_len;

    int err = 0;
    if ((err = aec_buffer_decode_with_offsets(strm, offsets))) {
        printf("ERROR: DEcoding failed (%d) %s\n", err, aec_get_error_message(err));
        return(1);
    }
    vector_print(offsets);
    return 0;
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
    int err = 0; \
    if ((err = aec_buffer_encode((strm_e))) != 0) { \
        printf("ERROR: Encoding failed (%d) %s\n", err, aec_get_error_message(err)); \
        exit(1); \
    } \
    for (size_t i = 0; i < (ctx)->obuf_len; ++i) { \
        if (i % (ctx)->block_size == 0) printf("\n"); \
        printf("%02x ", (ctx)->obuf[i]); \
    } \
    printf("\n"); \
}


#define PREPARE_ENCODE_WITH_OFFSETS(strm_eo, ctx, flags, offsets) \
{ \
    (strm_eo)->flags = flags; \
    (strm_eo)->rsi = (ctx)->rsi; \
    (strm_eo)->block_size = (ctx)->block_size; \
    (strm_eo)->bits_per_sample = (ctx)->bits_per_sample; \
    (strm_eo)->next_in = (ctx)->obuf; \
    (strm_eo)->avail_in = (ctx)->obuf_len; \
    (strm_eo)->next_out = (ctx)->ebuf; \
    (strm_eo)->avail_out = (ctx)->ebuf_len; \
    int err = 0; \
    if ((err = aec_buffer_encode_with_offsets((strm_eo), (offsets))) != 0) { \
        printf("ERROR: Encoding failed (%d) %s\n", err, aec_get_error_message(err)); \
        exit(1); \
    } \
    for (size_t i = 0; i < (ctx)->obuf_len; ++i) { \
        if (i % (ctx)->block_size == 0) printf("\n"); \
        printf("%02x ", (ctx)->obuf[i]); \
    } \
    printf("\n"); \
}


#define PREPARE_DECODE_WITH_OFFSETS(strm_do, ctx, flags, offsets) \
{ \
    (strm_do)->flags = (ctx)->flags; \
    (strm_do)->rsi = (ctx)->rsi; \
    (strm_do)->block_size = (ctx)->block_size; \
    (strm_do)->bits_per_sample = (ctx)->bits_per_sample; \
    (strm_do)->next_in = (ctx)->ebuf; \
    (strm_do)->avail_in = (ctx)->ebuf_len; \
    (strm_do)->next_out = (ctx)->dbuf; \
    (strm_do)->avail_out = (ctx)->dbuf_len; \
    int err = 0; \
    if ((err = aec_buffer_decode_with_offsets((strm_do), (offsets))) != 0) { \
        printf("ERROR: Decoding failed (%d) %s\n", err, aec_get_error_message(err)); \
        exit(1); \
    } \
    for (size_t i = 0; i < (strm_do)->total_out; ++i) { \
        if (i % (ctx)->block_size == 0) printf("\n"); \
        printf("%02x/%02x ", (ctx)->dbuf[i], (ctx)->obuf[i]); \
    } \
    for (size_t i = 0; i < (ctx)->obuf_len; ++i) { \
        assert((ctx)->obuf[i] == (ctx)->dbuf[i]); \
    } \
    printf("\n"); \
}


static int test_at(struct aec_context *ctx) 
{
    printf("%s\n", __PRETTY_FUNCTION__);
    int flags = ctx->flags;
    int nbytes = get_input_bytes(ctx->bits_per_sample);

    unsigned short *obuf = (unsigned short*) ctx->obuf;

    struct aec_stream strm_encode;
    PREPARE_ENCODE(&strm_encode, ctx, flags);

    struct aec_stream strm_decode;
    struct vector_t *offsets = vector_create(); \
    PREPARE_DECODE_WITH_OFFSETS(&strm_decode, ctx, flags, offsets);

    vector_print(offsets);

    size_t rsi_len = ctx->rsi * ctx->block_size * nbytes;
    unsigned char *rsi_buf = malloc(rsi_len);
    unsigned rsi_n = ctx->obuf_len / (ctx->rsi * ctx->block_size); // Number of full rsi blocks
    unsigned rsi_r = ctx->obuf_len % (ctx->rsi * ctx->block_size); // Remainder

    int i;
    for (i = 0; i < vector_size(offsets); ++i) {
        struct aec_stream strm_at;
        strm_at.flags = flags;
        strm_at.rsi = ctx->rsi;
        strm_at.block_size = ctx->block_size;
        strm_at.bits_per_sample = ctx->bits_per_sample;
        strm_at.next_in = ctx->ebuf;
        strm_at.avail_in = ctx->ebuf_len;
        strm_at.next_out = rsi_buf;
        strm_at.avail_out = rsi_len;

        printf("rsi: %d", i);
        int status = aec_rsi_at(&strm_at, offsets, i);
        if (status != AEC_OK) {
            printf("Error: %s\n", aec_get_error_message(status));
            return status;
        }
        for (int j = 0; j < strm_at.total_out; j++) {
            if (j == ctx->rsi * ctx->block_size * nbytes + j > ctx->obuf_len) {
                break;
            }
            if (j % (ctx->block_size * nbytes) == 0) printf("\n");

            printf("%02x/%02x ", rsi_buf[j], ctx->obuf[i * ctx->block_size * ctx->rsi * nbytes + j]);
            assert(rsi_buf[j] == ctx->obuf[i * ctx->block_size * ctx->rsi * nbytes + j]);
        }
        printf("\n");
    }

    vector_print(offsets); 
    vector_destroy(offsets);
    return 0;
}


int test_read(struct aec_context *ctx) 
{
    printf("%s\n", __PRETTY_FUNCTION__);
    int flags = ctx->flags;
    int nbytes = get_input_bytes(ctx->bits_per_sample);

    /*unsigned short *obuf = (unsigned short*) ctx->obuf;*/

    struct aec_stream strm_encode;
    PREPARE_ENCODE(&strm_encode, ctx, flags);

    struct aec_stream strm_decode;
    struct vector_t *offsets = vector_create();
    PREPARE_DECODE_WITH_OFFSETS(&strm_decode, ctx, flags, offsets);

    vector_print(offsets);

    size_t rsi_len = ctx->rsi * ctx->block_size * nbytes;
    unsigned char *rsi_buf = malloc(rsi_len);
    unsigned rsi_n = ctx->obuf_len / (ctx->rsi * ctx->block_size); // Number of full rsi blocks
    unsigned rsi_r = ctx->obuf_len % (ctx->rsi * ctx->block_size); // Remainder
    int err = 0;
  
    // Read data range
    struct aec_stream strm_read;
    strm_read.flags = ctx->flags;
    strm_read.rsi = ctx->rsi;
    strm_read.block_size = ctx->block_size;
    strm_read.bits_per_sample = ctx->bits_per_sample;
    strm_read.avail_in = ctx->ebuf_len;
    strm_read.next_in = ctx->ebuf; 
    strm_read.avail_out = ctx->dbuf_len;
    strm_read.next_out = ctx->dbuf;
    print_aec_stream_info(&strm_decode, __PRETTY_FUNCTION__);

    size_t pos = 17;
    size_t read_buf_size = 6;
    unsigned char *read_buf = malloc(read_buf_size);

    if ((err = aec_read(&strm_read, offsets, read_buf, read_buf_size, pos, read_buf_size)) != 0) {
        printf("Error: Failed reading chunk of data (%d)\n", err);
    }

    for (size_t i = 0; i < read_buf_size; ++i) {
        printf("%zu: %d %d\n", i, ctx->obuf[i + pos], read_buf[i]);
    }

    for (size_t i = 0; i < read_buf_size; ++i) {
        printf("assert(%d == %d)\n", ctx->obuf[i + pos], read_buf[i]);
        assert(ctx->obuf[i + pos] == read_buf[i]);
    }

    free(read_buf);
    vector_destroy(offsets);
    return 0;
}


void write_buffer(unsigned char* buf, size_t buf_len, const char* filename) {
    printf("%s\n", __PRETTY_FUNCTION__);
    printf("Writing %zu bytes in %s\n", buf_len, filename);
    FILE* f = fopen(filename, "wb");
    fwrite(buf, 1, buf_len, f);
    fclose(f);
}

// Tests 
int test_offsets(struct aec_context *ctx) {
    printf("%s\n", __PRETTY_FUNCTION__);
    int flags = ctx->flags;
    int nbytes = get_input_bytes(ctx->bits_per_sample);

    struct aec_stream strm;

    struct vector_t *encode_offsets = vector_create();
    PREPARE_ENCODE_WITH_OFFSETS(&strm, ctx, flags, encode_offsets);

    struct vector_t *decode_offsets = vector_create();
    PREPARE_DECODE_WITH_OFFSETS(&strm, ctx, flags, decode_offsets);

    vector_print(encode_offsets);
    vector_print(decode_offsets);

    assert(vector_equal(encode_offsets, decode_offsets) == 1);
    free(decode_offsets);
    free(encode_offsets);
    return 0;
}




int main(void)
{
    int status;
    struct aec_context ctx;

    /*AEC_DATA_SIGNED 1*/
    /*AEC_DATA_3BYTE 2*/
    /*AEC_DATA_MSB 4*/
    /*AEC_DATA_PREPROCESS 8*/
    /*AEC_RESTRICTED 16*/
    /*AEC_PAD_RSI 32*/
    /*AEC_NOT_ENFORCE 64*/

    ctx.nvalues = 67;
    /*ctx.flags = AEC_DATA_PREPROCESS | AEC_DATA_MSB; // Default value in ecCodes is 14*/
    ctx.flags = AEC_DATA_PREPROCESS; // Default value in ecCodes is 14
    ctx.rsi = 2;
    ctx.block_size = 16;
    ctx.bits_per_sample = 29;
    size_t bytes_per_sample = get_input_bytes(ctx.bits_per_sample);
    size_t input_size = ctx.nvalues * bytes_per_sample;
    ctx.obuf_len = input_size;
    ctx.ebuf_len = input_size * 2;
    ctx.dbuf_len = input_size;
    ctx.obuf = malloc(ctx.obuf_len);
    ctx.ebuf = malloc(ctx.ebuf_len);
    ctx.dbuf = malloc(ctx.dbuf_len);

    data_generator_zero(&ctx);
    data_generator_random(&ctx);
    data_generator_incr(&ctx);

    status = test_read(&ctx);
    status = test_at(&ctx);
    status = test_offsets(&ctx);

    free(ctx.obuf);
    free(ctx.ebuf);
    free(ctx.dbuf);
    return status;
}
