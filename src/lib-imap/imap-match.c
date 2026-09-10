/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* imap_match_init() logic originates from Cyrus, but the code is fully
   rewritten. */

#include "lib.h"
#include "array.h"
#include "imap-match.h"

#include <ctype.h>

/* Pattern matching is implemented as a Thompson-style NFA simulation.
   Each byte in the compressed pattern becomes one NFA state:

     LITERAL - must consume a matching byte, with inboxcase fallback
     PERCENT - may consume any number of non-separator bytes
     STAR    - may consume any number of bytes, including separators

   A virtual ACCEPT position sits at index n_states.  Simulation tracks the
   set of active positions in boolean arrays.  Epsilon transitions (skipping
   a PERCENT or STAR without consuming) are applied as a single forward pass,
   because the NFA is linear: each state can only epsilon-skip to i+1.

   Complexity is O(n_data * n_pattern), regardless of wildcard count or
   pattern shape, so there is no recursive backtracking and no way for a
   malicious pattern or mailbox name to trigger exponential CPU usage.

   This 2.4.1 backport keeps the historical byte-oriented matching model.
   The upstream fix operates on grapheme clusters, but backporting that would
   require additional Unicode matching changes outside the minimal ReDoS fix. */

enum imap_match_nfa_type {
	IMAP_MATCH_NFA_LITERAL = 0,
	IMAP_MATCH_NFA_PERCENT,
	IMAP_MATCH_NFA_STAR
};

struct imap_match_nfa_state {
	enum imap_match_nfa_type type;
	bool sep_accept;
	unsigned char ch;
};

struct imap_match_pattern {
	const char *pattern;
	bool inboxcase;

	unsigned int n_states;
	struct imap_match_nfa_state *states;
};

struct imap_match_glob {
	pool_t pool;

	struct imap_match_pattern *patterns;

	char sep;
	char patterns_data[FLEXIBLE_ARRAY_MEMBER];
};

/* name of "INBOX" - must not have repeated substrings */
static const char inbox[] = "INBOX";
#define INBOXLEN (sizeof(inbox) - 1)

struct imap_match_glob *
imap_match_init(pool_t pool, const char *pattern,
		bool inboxcase, char separator)
{
	const char *patterns[2];

	patterns[0] = pattern;
	patterns[1] = NULL;
	return imap_match_init_multiple(pool, patterns, inboxcase, separator);
}

static const char *pattern_compress(const char *pattern)
{
	char *dest, *ret;

	dest = ret = t_strdup_noconst(pattern);

	/* @UNSAFE: compress the pattern */
	while (*pattern != '\0') {
		if (*pattern == '*' || *pattern == '%') {
			/* remove duplicate hierarchy wildcards */
			while (*pattern == '%') pattern++;

			/* "%*" -> "*" */
			if (*pattern == '*') {
				/* remove duplicate wildcards */
				while (*pattern == '*' || *pattern == '%')
					pattern++;
				*dest++ = '*';
			} else {
				*dest++ = '%';
			}
		} else {
			*dest++ = *pattern++;
		}
	}
	*dest = '\0';
	return ret;
}

static bool pattern_is_inboxcase(const char *pattern, char separator)
{
	const char *p = pattern, *inboxp = inbox;

	/* skip over exact matches */
	while (*inboxp == i_toupper(*p) && *p != '\0') {
		inboxp++; p++;
	}
	if (*p != '%') {
		return *p == '*' || *p == separator ||
			(*inboxp == '\0' && *p == '\0');
	}

	/* handle 'I%B%X' style checks */
	for (; *p != '\0' && *p != '*' && *p != separator; p++) {
		if (*p != '%') {
			inboxp = strchr(inboxp, i_toupper(*p));
			if (inboxp == NULL)
				return FALSE;

			if (*++inboxp == '\0') {
				/* now check that it doesn't end with
				   any invalid chars */
				if (*++p == '%') p++;
				if (*p != '\0' && *p != '*' &&
				    *p != separator)
					return FALSE;
				break;
			}
		}
	}
	return TRUE;
}

static void
imap_match_compile(pool_t pool, struct imap_match_pattern *pat, char sep)
{
	unsigned int i;

	pat->n_states = strlen(pat->pattern);
	pat->states = pat->n_states == 0 ? NULL :
		p_new(pool, struct imap_match_nfa_state, pat->n_states);

	for (i = 0; i < pat->n_states; i++) {
		struct imap_match_nfa_state *state = &pat->states[i];
		unsigned char ch = (unsigned char)pat->pattern[i];

		if (ch == '%')
			state->type = IMAP_MATCH_NFA_PERCENT;
		else if (ch == '*')
			state->type = IMAP_MATCH_NFA_STAR;
		else {
			state->type = IMAP_MATCH_NFA_LITERAL;
			state->ch = ch;
		}
	}

	for (i = pat->n_states; i > 0; i--) {
		unsigned int idx = i - 1;
		const struct imap_match_nfa_state *state = &pat->states[idx];
		bool consume_sep =
			state->type == IMAP_MATCH_NFA_STAR ||
			(state->type == IMAP_MATCH_NFA_LITERAL &&
			 state->ch == (unsigned char)sep);
		bool eps_skippable =
			state->type == IMAP_MATCH_NFA_PERCENT ||
			state->type == IMAP_MATCH_NFA_STAR;
		bool next_sep_accept =
			idx + 1 < pat->n_states ?
			pat->states[idx + 1].sep_accept : FALSE;

		pat->states[idx].sep_accept =
			consume_sep || (eps_skippable && next_sep_accept);
	}
}

static struct imap_match_glob *
imap_match_init_multiple_real(pool_t pool, const char *const *patterns,
			      bool inboxcase, char separator)
{
	struct imap_match_glob *glob;
	struct imap_match_pattern *match_patterns;
	unsigned int i, patterns_count;
	size_t len, pos, patterns_data_len = 0;

	patterns_count = str_array_length(patterns);
	match_patterns = p_new(pool, struct imap_match_pattern,
			       patterns_count + 1);

	/* compress the patterns */
	for (i = 0; i < patterns_count; i++) {
		match_patterns[i].pattern = pattern_compress(patterns[i]);
		match_patterns[i].inboxcase = inboxcase &&
			pattern_is_inboxcase(match_patterns[i].pattern,
					     separator);

		patterns_data_len += strlen(match_patterns[i].pattern) + 1;
	}
	patterns_count = i;

	/* now we know how much memory we need */
	glob = p_malloc(pool, sizeof(struct imap_match_glob) +
			patterns_data_len);
	glob->pool = pool;
	glob->sep = separator;

	/* copy pattern strings to our allocated memory and compile NFAs */
	for (i = 0, pos = 0; i < patterns_count; i++) {
		len = strlen(match_patterns[i].pattern) + 1;
		i_assert(pos + len <= patterns_data_len);

		/* @UNSAFE */
		memcpy(glob->patterns_data + pos,
		       match_patterns[i].pattern, len);
		match_patterns[i].pattern = glob->patterns_data + pos;
		pos += len;

		imap_match_compile(pool, &match_patterns[i], separator);
	}
	glob->patterns = match_patterns;
	return glob;
}

struct imap_match_glob *
imap_match_init_multiple(pool_t pool, const char *const *patterns,
			 bool inboxcase, char separator)
{
	struct imap_match_glob *glob;

	if (pool->datastack_pool) {
		return imap_match_init_multiple_real(pool, patterns,
						     inboxcase, separator);
	}
	T_BEGIN {
		glob = imap_match_init_multiple_real(pool, patterns,
						     inboxcase, separator);
	} T_END;
	return glob;
}

void imap_match_deinit(struct imap_match_glob **glob)
{
	struct imap_match_pattern *p;

	if (glob == NULL || *glob == NULL)
		return;

	for (p = (*glob)->patterns; p->pattern != NULL; p++) {
		if (p->states != NULL)
			p_free((*glob)->pool, p->states);
	}
	p_free((*glob)->pool, (*glob)->patterns);
	p_free((*glob)->pool, *glob);
	*glob = NULL;
}

static struct imap_match_glob *
imap_match_dup_real(pool_t pool, const struct imap_match_glob *glob)
{
	ARRAY_TYPE(const_string) patterns;
	const struct imap_match_pattern *p;
	bool inboxcase = FALSE;

	t_array_init(&patterns, 8);
	for (p = glob->patterns; p->pattern != NULL; p++) {
		if (p->inboxcase)
			inboxcase = TRUE;
		array_push_back(&patterns, &p->pattern);
	}
	array_append_zero(&patterns);
	return imap_match_init_multiple_real(pool, array_front(&patterns),
					     inboxcase, glob->sep);
}

struct imap_match_glob *
imap_match_dup(pool_t pool, const struct imap_match_glob *glob)
{
	struct imap_match_glob *new_glob;

	if (pool->datastack_pool) {
		return imap_match_dup_real(pool, glob);
	} else {
		T_BEGIN {
			new_glob = imap_match_dup_real(pool, glob);
		} T_END;
		return new_glob;
	}
}

bool imap_match_globs_equal(const struct imap_match_glob *glob1,
			    const struct imap_match_glob *glob2)
{
	const struct imap_match_pattern *p1 = glob1->patterns;
	const struct imap_match_pattern *p2 = glob2->patterns;

	if (glob1->sep != glob2->sep)
		return FALSE;

	for (; p1->pattern != NULL && p2->pattern != NULL; p1++, p2++) {
		if (strcmp(p1->pattern, p2->pattern) != 0)
			return FALSE;
		if (p1->inboxcase != p2->inboxcase)
			return FALSE;
	}
	return p1->pattern == p2->pattern;
}

static bool
literal_matches(const struct imap_match_nfa_state *state,
		unsigned char data_ch, bool inboxcase_pos)
{
	if (state->ch == data_ch)
		return TRUE;
	return inboxcase_pos &&
		i_toupper(data_ch) == i_toupper(state->ch);
}

static void
nfa_eps_close(const struct imap_match_pattern *pat, bool *bits)
{
	unsigned int i;

	for (i = 0; i < pat->n_states; i++) {
		if (!bits[i])
			continue;
		if (pat->states[i].type == IMAP_MATCH_NFA_PERCENT ||
		    pat->states[i].type == IMAP_MATCH_NFA_STAR)
			bits[i + 1] = TRUE;
	}
}

static enum imap_match_result
imap_match_pattern_run(const struct imap_match_pattern *pat,
		       const char *data, char sep, bool inboxcase_pattern)
{
	const char *inboxcase_end = data;
	unsigned int n_bits = pat->n_states + 1;
	enum imap_match_result result = IMAP_MATCH_NO;
	bool parent_flag = FALSE;
	bool data_ends_with_sep = FALSE;
	bool *cur, *next;
	const unsigned char *p;

	if (inboxcase_pattern &&
	    strncasecmp(data, inbox, INBOXLEN) == 0 &&
	    (data[INBOXLEN] == '\0' || data[INBOXLEN] == sep)) {
		inboxcase_end += INBOXLEN;
	}

	cur = t_new(bool, n_bits);
	next = t_new(bool, n_bits);
	memset(cur, 0, n_bits * sizeof(*cur));
	memset(next, 0, n_bits * sizeof(*next));

	cur[0] = TRUE;
	nfa_eps_close(pat, cur);

	for (p = (const unsigned char *)data; *p != '\0'; p++) {
		unsigned int i;
		unsigned char ch = *p;
		bool ch_is_sep = ch == (unsigned char)sep;
		bool inboxcase_pos = (const char *)p < inboxcase_end;

		if (ch_is_sep && cur[pat->n_states])
			parent_flag = TRUE;

		memset(next, 0, n_bits * sizeof(*next));
		for (i = 0; i < pat->n_states; i++) {
			const struct imap_match_nfa_state *state;

			if (!cur[i])
				continue;

			state = &pat->states[i];
			switch (state->type) {
			case IMAP_MATCH_NFA_LITERAL:
				if (literal_matches(state, ch, inboxcase_pos))
					next[i + 1] = TRUE;
				break;
			case IMAP_MATCH_NFA_PERCENT:
				if (!ch_is_sep)
					next[i] = TRUE;
				break;
			case IMAP_MATCH_NFA_STAR:
				next[i] = TRUE;
				break;
			}
		}

		{
			bool *tmp = cur;
			cur = next;
			next = tmp;
		}
		nfa_eps_close(pat, cur);
		data_ends_with_sep = ch_is_sep;
	}

	if (cur[pat->n_states])
		result = IMAP_MATCH_YES;
	else {
		unsigned int i;
		bool has_nonaccept = FALSE;
		bool has_sep_accept = FALSE;

		for (i = 0; i < pat->n_states; i++) {
			if (!cur[i])
				continue;
			has_nonaccept = TRUE;
			if (pat->states[i].sep_accept) {
				has_sep_accept = TRUE;
				break;
			}
		}

		if (has_nonaccept && (data_ends_with_sep || has_sep_accept))
			result |= IMAP_MATCH_CHILDREN;
		if (parent_flag)
			result |= IMAP_MATCH_PARENT;
	}

	return result;
}

enum imap_match_result
imap_match(struct imap_match_glob *glob, const char *data)
{
	unsigned int i;
	enum imap_match_result ret, match;

	match = IMAP_MATCH_NO;
	for (i = 0; glob->patterns[i].pattern != NULL; i++) {
		T_BEGIN {
			ret = imap_match_pattern_run(&glob->patterns[i], data,
						     glob->sep,
						     glob->patterns[i].inboxcase);
		} T_END;
		if (ret == IMAP_MATCH_YES)
			return IMAP_MATCH_YES;

		match |= ret;
	}

	return match;
}
