/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef NM_TEST_HELPERS_H
#define NM_TEST_HELPERS_H

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

#define FAIL(test_name, fmt, ...) \
    G_STMT_START { \
        g_error ("%s:%d: FAIL[%s]: " fmt, __FILE__, __LINE__, test_name, ## __VA_ARGS__); \
    } G_STMT_END

#define ASSERT(x, test_name, fmt, ...) \
    G_STMT_START { \
        if (!(x)) { \
            FAIL (test_name, fmt, ## __VA_ARGS__); \
        } \
    } G_STMT_END

#endif /* NM_TEST_HELPERS_H */

