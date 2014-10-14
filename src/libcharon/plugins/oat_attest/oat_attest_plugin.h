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
 * @defgroup oat_attest oat_attest
 * @ingroup cplugins
 *
 * @defgroup oat_attest_plugin oat_attest_plugin
 * @{ @ingroup oat_attest
 */

#ifndef OAT_ATTEST_PLUGIN_H_
#define OAT_ATTEST_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct oat_attest_plugin_t oat_attest_plugin_t;

/**
 * Plugin for attesting a peer with OpenAttestation.
 */
struct oat_attest_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** OAT_ATTEST_PLUGIN_H_ @}*/
