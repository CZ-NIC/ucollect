#!/usr/bin/env lua

--[[
Copyright 2014, CZ.NIC z.s.p.o. (http://www.nic.cz/)

This script is part of majordomo plugin for ucollect

NUCI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

NUCI is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NUCI.  If not, see <http://www.gnu.org/licenses/>.
]]

require("os");

package.path = package.path .. ';/usr/share/lcollect/lua/?.lua'
require("majordomo_lib");

local CMD_INVALIDATE = "invalidate";
local CMD_PRECACHE = "precache";

function invalidate(db_path)
	os.execute("rm '" .. db_path .. "/majordomo_serialized_'*");
end

function precache(db_path, ml_mac, ml_dns)
	local macdb = get_inst_macdb();
	macdb:deserialize();

	local handles = { };
	table.insert(handles, io.popen("/bin/ls '" .. db_path .. "/" ..  DAILY_PREFIX .."'*", "r"));
	table.insert(handles, io.popen("/bin/ls '" .. db_path .. "/" ..  HOURLY_PREFIX .."'*", "r"));
	table.insert(handles, io.popen("/bin/ls '" .. db_path .. "/" ..  MONTHLY_PREFIX .."'*", "r"));

	for _, handle in ipairs(handles) do
		for filename in handle:lines() do
			local ptrdb = get_inst_ptrdb(); -- ptrdb is per file
			local changed = false;
			local tmp_filename = "/tmp/_tmp_edit"..string.gsub(filename, "/", "_");
			local tmp_file = io.open(tmp_filename, "w");

			local file = io.open(filename, "r");
			for line in file:lines() do
				data = parse_line(line);
				if ml_mac then
					macdb:check(data[DD_SRC]);
					macdb:lookup(data[DD_SRC]);
				end
				if ml_dns then
					if not data[DD_RESOLVED] then
						changed = true;
						local ptr = ptrdb:lookup(data[DD_DST]);
						data[DD_RESOLVED] = ptr or CACHE_EMPTY_NAME;
						tmp_file:write(restore_line(data).."\n");
					end
				end
			end

			file:close();
			tmp_file:close();
			if changed then
				os.rename(tmp_filename, filename);
			else
				os.remove(tmp_filename);
			end
		end
		handle:close();
	end

	macdb:serialize();
end

function main()
	local db_path, make_lookup_mac, make_lookup_dns, _ = majordomo_get_configuration();

	if #arg ~= 1 then
		io.stderr:write(string.format("Usage: %s (%s|%s)\n", arg[0], CMD_PRECACHE, CMD_INVALIDATE));
		os.exit(1);
	end

	if arg[1] == CMD_INVALIDATE then
		invalidate(db_path);

	elseif arg[1] == CMD_PRECACHE then
		if make_lookup_mac or make_lookup_dns then
			precache(db_path, make_lookup_mac, make_lookup_dns);
		else
			io.stderr:write("Precache: Lookup is disabled\n");
			os.exit(0);
		end
	end
end

main();
