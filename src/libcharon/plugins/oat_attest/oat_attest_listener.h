/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
 * Copyright (C) 2014 Politecnico di Torino, Italy
 *                    TORSEC group -- http://security.polito.it
 *
 * Author: Roberto Sassu <roberto.sassu@polito.it>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup oat_attest_listener oat_attest_listener
 * @{ @ingroup oat_attest
 */

#ifndef CERTEXPIRE_LISTENER_H_
#define CERTEXPIRE_LISTENER_H_

#include <bus/listeners/listener.h>

typedef struct oat_attest_listener_t oat_attest_listener_t;

/**
 * Listener collecting certificate expire information after authentication.
 */
struct oat_attest_listener_t {

	/**
	 * Implements listener_t interface.
	 */
	listener_t listener;

	/**
	 * Destroy a oat_attest_listener_t.
	 */
	void (*destroy)(oat_attest_listener_t *this);
};

/**
 * Create a oat_attest_listener instance.
 *
 * @return				listener instance
 */
oat_attest_listener_t *oat_attest_listener_create();

#endif /** CERTEXPIRE_LISTENER_H_ @}*/
