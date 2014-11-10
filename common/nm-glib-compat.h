/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_GLIB_COMPAT_H__
#define __NM_GLIB_COMPAT_H__

#include <glib.h>
#include <glib-object.h>


#if !GLIB_CHECK_VERSION(2,34,0)

#define g_clear_pointer(pp, destroy)	  \
	G_STMT_START { \
		G_STATIC_ASSERT (sizeof *(pp) == sizeof (gpointer)); \
		/* Only one access, please */ \
		gpointer *_pp = (gpointer *) (pp); \
		gpointer _p; \
		/* This assignment is needed to avoid a gcc warning */ \
		GDestroyNotify _destroy = (GDestroyNotify) (destroy); \
	  \
		(void) (0 ? (gpointer) *(pp) : 0); \
		do \
			_p = g_atomic_pointer_get (_pp); \
		while G_UNLIKELY (!g_atomic_pointer_compare_and_exchange (_pp, _p, NULL)); \
	  \
		if (_p) \
			_destroy (_p); \
	} G_STMT_END

#endif

#endif  /* __NM_GLIB_COMPAT_H__ */
