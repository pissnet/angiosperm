/*
 *  Copyright (C) 2022 Noisytoot
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "stdinc.h"
#include "modules.h"
#include "s_serv.h"
#include "s_newconf.h"

static char cap_id_desc[] = "Provides the letspiss.net/id client capability";

static bool cap_oper_id_visible(struct Client *);
static void cap_id_outbound_msgbuf(void *);
static void cap_id_umode_changed(void *);
static void cap_id_cap_change(void *);

static unsigned CLICAP_ID;
static unsigned CLICAP_OPER_ID;

static struct ClientCapability capdata_oper_id = {
	.visible = cap_oper_id_visible,
};

mapi_cap_list_av2 cap_id_caps[] = {
	{ MAPI_CAP_CLIENT, "letspiss.net/id", NULL, &CLICAP_ID },
	{ MAPI_CAP_CLIENT, "?oper_id", &capdata_oper_id, &CLICAP_OPER_ID },
	{ 0, NULL, NULL, NULL },
};

mapi_hfn_list_av1 cap_id_hfnlist[] = {
	{ "outbound_msgbuf", cap_id_outbound_msgbuf, HOOK_NORMAL },
	{ "umode_changed", cap_id_umode_changed, HOOK_MONITOR },
	{ "cap_change", cap_id_cap_change, HOOK_MONITOR },
	{ NULL, NULL, 0 },
};

static bool
cap_oper_id_visible(struct Client *client)
{
	return false;
}

static void
cap_id_outbound_msgbuf(void *data_)
{
	hook_data *data = data_;
	struct MsgBuf *msgbuf = data->arg1;

	if (data->client != NULL)
		msgbuf_append_tag(msgbuf, "letspiss.net/id", data->client->id, CLICAP_OPER_ID);
}

static inline void
update_clicap_oper_id(struct Client *client)
{
	client->localClient->caps &= ~CLICAP_OPER_ID;
	if (client->localClient->caps & CLICAP_ID && HasPrivilege(client, "auspex:id"))
	{
		client->localClient->caps |= CLICAP_OPER_ID;
	}
}

static void
cap_id_umode_changed(void *data_)
{
	hook_data_umode_changed *data = data_;

	if (!MyClient(data->client))
		return;

	update_clicap_oper_id(data->client);
}

static void
cap_id_cap_change(void *data_)
{
	hook_data_cap_change *data = data_;

	update_clicap_oper_id(data->client);
}

static int
modinit(void)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		struct Client *client = ptr->data;

		update_clicap_oper_id(client);
	}

	return 0;
}

DECLARE_MODULE_AV2(cap_id, modinit, NULL, NULL, NULL, cap_id_hfnlist, cap_id_caps, NULL, cap_id_desc);
