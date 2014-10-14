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

#include "oat_attest_plugin.h"

#include "oat_attest_listener.h"

#include <daemon.h>

typedef struct private_oat_attest_plugin_t private_oat_attest_plugin_t;

/**
 * Private data of oat_attest plugin
 */
struct private_oat_attest_plugin_t {

	/**
	 * Implements plugin interface
	 */
	oat_attest_plugin_t public;

	/**
	 * Listener collecting expire information
	 */
	oat_attest_listener_t *listener;
};

METHOD(plugin_t, get_name, char*,
	private_oat_attest_plugin_t *this)
{
	return "oat_attest";
}

/**
 * Register listener
 */
static bool plugin_cb(private_oat_attest_plugin_t *this,
		      plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		charon->bus->add_listener(charon->bus, &this->listener->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_oat_attest_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "oat_attest"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_oat_attest_plugin_t *this)
{
	this->listener->destroy(this->listener);
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *oat_attest_plugin_create()
{
	private_oat_attest_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);
	this->listener = oat_attest_listener_create();

	return &this->public.plugin;
}
