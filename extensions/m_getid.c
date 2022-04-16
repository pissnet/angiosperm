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
#include "numeric.h"
#include "send.h"
#include "hash.h"
#include "s_newconf.h"

static char getid_desc[] = "Provides the GETID command to resolve a nick or server name to a UID or SID";

static void m_getid(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message getid_msgtab = {
	"GETID", 0, 0, 0, 0,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {m_getid, 0}}
};

mapi_clist_av1 getid_clist[] = { &getid_msgtab, NULL };

DECLARE_MODULE_AV2(getid, NULL, NULL, getid_clist, NULL, NULL, NULL, NULL, getid_desc);

/*
** m_getid
**	parv[1] = optional client, defaults to sender
**	parv[2] = optional nonce
*/
static void
m_getid(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *target_name;
	struct Client *target_p;
	const char *nonce;

	if(!HasPrivilege(source_p, "auspex:id"))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "getid");
		return;
	}

        /* Default to sender if target not specified */
	if ((parc < 1) || EmptyString(parv[1]))
	{
		target_p = client_p;
	} else
	{
		target_name = parv[1];

		if (!(target_p = find_client(target_name)))
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), target_name);
			return;
		}
	}

	if ((parc < 2) || EmptyString(parv[2]))
	{
		nonce = NULL;
	} else
	{
		nonce = parv[2];
	}

	if (nonce)
	{
		sendto_one_notice(client_p, ":GETID: %s is %s, nonce: %s", target_p->name, target_p->id, nonce);
	} else
	{
		sendto_one_notice(client_p, ":GETID: %s is %s", target_p->name, target_p->id);
	}
}
