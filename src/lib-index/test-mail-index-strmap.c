/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "crc32.h"
#include "hash2.h"
#include "test-common.h"
#include "test-mail-index.h"
#include "write-full.h"
#include "xxh64.h"
#include "mail-index-strmap.h"
#include "mail-index-util.h"

struct strmap_test_context {
	const char *key;
	unsigned int key_compare_count;
};

static bool
strmap_test_key_compare(const char *key,
			const struct mail_index_strmap_rec *rec, void *context)
{
	struct strmap_test_context *ctx = context;

	ctx->key_compare_count++;
	return strcmp(key, ctx->key) == 0 && rec->str_idx == 1;
}

static int
strmap_test_rec_compare(const struct mail_index_strmap_rec *rec1,
			const struct mail_index_strmap_rec *rec2,
			void *context ATTR_UNUSED)
{
	return rec1->str_idx == rec2->str_idx ? 1 : 0;
}

static void
strmap_test_remap(const uint32_t *idx_map ATTR_UNUSED,
		  unsigned int old_count ATTR_UNUSED,
		  unsigned int new_count ATTR_UNUSED,
		  void *context ATTR_UNUSED)
{
}

static void
strmap_test_create_index(struct mail_index **index_r,
			 struct mail_index_view **view_r, uint32_t uid_validity)
{
	struct mail_index_transaction *trans;
	uint32_t seq;

	*index_r = test_mail_index_init(TRUE);
	*view_r = mail_index_view_open(*index_r);
	trans = mail_index_transaction_begin(*view_r,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	mail_index_append(trans, 1, &seq);
	mail_index_append(trans, 2, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(view_r);
	*view_r = mail_index_view_open(*index_r);
}

static uint32_t
strmap_test_hash(const char *key, uint8_t version, uint64_t hash_iv)
{
	uint32_t value;

	if (version == MAIL_INDEX_STRMAP_VERSION_V1)
		value = crc32_str(key) ^ 0xffffffffU;
	else
		value = xxh64_to_32(xxh64_data(key, strlen(key), hash_iv));
	return value == 0 ? 1 : value;
}

static void
strmap_test_write_file(const char *path, uint8_t version,
		       uint32_t uid_validity, uint64_t hash_iv, const char *key)
{
	struct mail_index_strmap_header hdr;
	uint8_t packed[MAIL_INDEX_PACK_MAX_SIZE * 2], *p = packed;
	uint32_t block_size, hash, str_idx = 1;
	size_t hdr_size, data_size;
	int fd;

	i_zero(&hdr);
	hdr.version = version;
	hdr.uid_validity = uid_validity;
	if (version == MAIL_INDEX_STRMAP_VERSION_V2) {
#ifndef WORDS_BIGENDIAN
		hdr.compat_flags = MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif
		hdr.hash_iv = hash_iv;
		hdr_size = MAIL_INDEX_STRMAP_HEADER_V2_SIZE;
	} else {
		hdr_size = MAIL_INDEX_STRMAP_HEADER_V1_SIZE;
	}

	mail_index_pack_num(&p, 0);
	mail_index_pack_num(&p, 0);
	data_size = (size_t)(p - packed) + sizeof(hash) + sizeof(str_idx);
	block_size = mail_index_uint32_to_offset((uint32_t)data_size << 2);
	hash = strmap_test_hash(key, version, hash_iv);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	test_assert(write_full(fd, &hdr, hdr_size) == 0);
	test_assert(write_full(fd, &block_size, sizeof(block_size)) == 0);
	test_assert(write_full(fd, packed, p - packed) == 0);
	test_assert(write_full(fd, &hash, sizeof(hash)) == 0);
	test_assert(write_full(fd, &str_idx, sizeof(str_idx)) == 0);
	i_close_fd(&fd);
}

static void strmap_test_round_trip(uint8_t version)
{
	const uint32_t uid_validity = 0x12345678;
	const uint64_t hash_iv = UINT64_C(0x0123456789abcdef);
	const char *key = "persisted-key";
	struct strmap_test_context ctx = { .key = key };
	struct mail_index_strmap *strmap;
	struct mail_index_strmap_view *strmap_view;
	struct mail_index_strmap_view_sync *sync;
	struct mail_index *index;
	struct mail_index_view *view;
	const ARRAY_TYPE(mail_index_strmap_rec) *recs;
	const struct mail_index_strmap_rec *rec;
	const struct hash2_table *hash;
	const char *path;
	struct stat st_before, st_after;
	uint32_t last_uid;
	unsigned int count;
	bool enable_xxh64 = version == MAIL_INDEX_STRMAP_VERSION_V2;

	test_begin(t_strdup_printf("mail index strmap v%u header round trip",
				   version));
	strmap_test_create_index(&index, &view, uid_validity);
	path = t_strconcat(test_mail_index_get_dir(),
			   "/test.dovecot.index.strmap", NULL);
	strmap_test_write_file(path, version, uid_validity, hash_iv, key);
	test_assert(stat(path, &st_before) == 0);

	strmap = mail_index_strmap_init(index, ".strmap", enable_xxh64);
	strmap_view = mail_index_strmap_view_open(strmap, view,
		strmap_test_key_compare, strmap_test_rec_compare,
		strmap_test_remap, &ctx, &recs, &hash);
	sync = mail_index_strmap_view_sync_init(strmap_view, &last_uid);
	test_assert(last_uid == 1);
	rec = array_get(recs, &count);
	test_assert(count == 1 && rec[0].uid == 1 && rec[0].str_idx == 1);

	/* Reusing the persisted index proves v1 CRC32 compatibility and that
	   the v2-only tail was copied from offset 8 into the correct fields. */
	mail_index_strmap_view_sync_add(sync, 2, 0, key);
	rec = array_get(recs, &count);
	test_assert(count == 2 && rec[1].str_idx == 1);
	test_assert(ctx.key_compare_count > 0);
	mail_index_strmap_view_sync_commit(&sync);
	test_assert(stat(path, &st_after) == 0);
	test_assert(st_before.st_ino == st_after.st_ino);

	mail_index_strmap_view_close(&strmap_view);
	mail_index_strmap_deinit(&strmap);
	ctx.key_compare_count = 0;

	strmap = mail_index_strmap_init(index, ".strmap", enable_xxh64);
	strmap_view = mail_index_strmap_view_open(strmap, view,
		strmap_test_key_compare, strmap_test_rec_compare,
		strmap_test_remap, &ctx, &recs, &hash);
	sync = mail_index_strmap_view_sync_init(strmap_view, &last_uid);
	rec = array_get(recs, &count);
	test_assert(last_uid == 2 && count == 2);
	test_assert(rec[0].str_idx == 1 && rec[1].str_idx == 1);
	mail_index_strmap_view_sync_commit(&sync);
	test_assert(stat(path, &st_after) == 0);
	test_assert(st_before.st_ino == st_after.st_ino);

	mail_index_strmap_view_close(&strmap_view);
	mail_index_strmap_deinit(&strmap);
	mail_index_view_close(&view);
	test_mail_index_deinit(&index);
	test_end();
}

static void test_mail_index_strmap_round_trip(void)
{
	strmap_test_round_trip(MAIL_INDEX_STRMAP_VERSION_V1);
	strmap_test_round_trip(MAIL_INDEX_STRMAP_VERSION_V2);
}

static void test_mail_index_strmap_truncated_v2_header(void)
{
	const uint32_t uid_validity = 0x12345678;
	struct mail_index_strmap_header hdr;
	struct strmap_test_context ctx = { .key = "unused" };
	struct mail_index_strmap *strmap;
	struct mail_index_strmap_view *strmap_view;
	struct mail_index_strmap_view_sync *sync;
	struct mail_index *index;
	struct mail_index_view *view;
	const ARRAY_TYPE(mail_index_strmap_rec) *recs;
	const struct hash2_table *hash;
	const char *path;
	uint32_t last_uid;
	const size_t sizes[] = { 0, MAIL_INDEX_STRMAP_HEADER_V1_SIZE };
	int fd;

	test_begin("mail index strmap truncated v2 header");
	strmap_test_create_index(&index, &view, uid_validity);
	path = t_strconcat(test_mail_index_get_dir(),
			   "/test.dovecot.index.strmap", NULL);
	i_zero(&hdr);
	hdr.version = MAIL_INDEX_STRMAP_VERSION_V2;
	hdr.uid_validity = uid_validity;
	for (unsigned int i = 0; i < N_ELEMENTS(sizes); i++) {
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd == -1)
			i_fatal("open(%s) failed: %m", path);
		test_assert(write_full(fd, &hdr, sizes[i]) == 0);
		i_close_fd(&fd);

		strmap = mail_index_strmap_init(index, ".strmap", TRUE);
		strmap_view = mail_index_strmap_view_open(strmap, view,
			strmap_test_key_compare, strmap_test_rec_compare,
			strmap_test_remap, &ctx, &recs, &hash);
		test_expect_error_string("Corrupted strmap index file");
		sync = mail_index_strmap_view_sync_init(strmap_view, &last_uid);
		test_expect_no_more_errors();
		test_assert(access(path, F_OK) < 0 && errno == ENOENT);
		mail_index_strmap_view_sync_rollback(&sync);

		mail_index_strmap_view_close(&strmap_view);
		mail_index_strmap_deinit(&strmap);
	}
	mail_index_view_close(&view);
	test_mail_index_deinit(&index);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_strmap_round_trip,
		test_mail_index_strmap_truncated_v2_header,
		NULL
	};

	test_dir_init("mail-index-strmap");
	return test_run(test_functions);
}
